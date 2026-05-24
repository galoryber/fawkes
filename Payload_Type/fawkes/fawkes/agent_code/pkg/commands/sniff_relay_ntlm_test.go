package commands

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

// buildNTLMHeader constructs the first 12 bytes of an NTLM message.
func buildNTLMHeader(msgType uint32) []byte {
	h := make([]byte, 12)
	copy(h[0:8], sniffNTLMSig) // "NTLMSSP\x00"
	binary.LittleEndian.PutUint32(h[8:12], msgType)
	return h
}

// --- asn1WrapLength tests ---

func TestAsn1WrapLength_Short(t *testing.T) {
	got := asn1WrapLength(5)
	if len(got) != 1 || got[0] != 5 {
		t.Errorf("asn1WrapLength(5) = %v, want [0x05]", got)
	}
}

func TestAsn1WrapLength_Zero(t *testing.T) {
	got := asn1WrapLength(0)
	if len(got) != 1 || got[0] != 0 {
		t.Errorf("asn1WrapLength(0) = %v, want [0x00]", got)
	}
}

func TestAsn1WrapLength_127(t *testing.T) {
	got := asn1WrapLength(127)
	if len(got) != 1 || got[0] != 127 {
		t.Errorf("asn1WrapLength(127) = %v, want [0x7f]", got)
	}
}

func TestAsn1WrapLength_128(t *testing.T) {
	// 128 requires 2-byte long form: 0x81 0x80
	got := asn1WrapLength(128)
	if len(got) != 2 || got[0] != 0x81 || got[1] != 0x80 {
		t.Errorf("asn1WrapLength(128) = %v, want [0x81, 0x80]", got)
	}
}

func TestAsn1WrapLength_255(t *testing.T) {
	got := asn1WrapLength(255)
	if len(got) != 2 || got[0] != 0x81 || got[1] != 0xff {
		t.Errorf("asn1WrapLength(255) = %v, want [0x81, 0xff]", got)
	}
}

func TestAsn1WrapLength_256(t *testing.T) {
	// 256 requires 3-byte long form: 0x82 0x01 0x00
	got := asn1WrapLength(256)
	if len(got) != 3 || got[0] != 0x82 || got[1] != 0x01 || got[2] != 0x00 {
		t.Errorf("asn1WrapLength(256) = %v, want [0x82, 0x01, 0x00]", got)
	}
}

// --- relayASN1Wrap / asn1WrapSequence / asn1WrapOctetString tests ---

func TestRelayASN1Wrap_TagAndContent(t *testing.T) {
	content := []byte{0x01, 0x02, 0x03}
	got := relayASN1Wrap(0x30, content)
	if len(got) != 5 {
		t.Fatalf("length = %d, want 5 (1 tag + 1 length + 3 content)", len(got))
	}
	if got[0] != 0x30 {
		t.Errorf("tag = 0x%02x, want 0x30", got[0])
	}
	if got[1] != 3 {
		t.Errorf("length byte = %d, want 3", got[1])
	}
	if !bytes.Equal(got[2:], content) {
		t.Errorf("content = %v, want %v", got[2:], content)
	}
}

func TestAsn1WrapSequence_Tag(t *testing.T) {
	content := []byte{0xaa}
	got := asn1WrapSequence(content)
	if got[0] != 0x30 {
		t.Errorf("SEQUENCE tag = 0x%02x, want 0x30", got[0])
	}
}

func TestAsn1WrapOctetString_Tag(t *testing.T) {
	content := []byte{0xbb}
	got := asn1WrapOctetString(content)
	if got[0] != 0x04 {
		t.Errorf("OCTET STRING tag = 0x%02x, want 0x04", got[0])
	}
}

func TestAsn1WrapExplicit_ContextTag(t *testing.T) {
	content := []byte{0xcc}
	got := asn1WrapExplicit(0, content)
	// [0] EXPLICIT = 0xa0
	if got[0] != 0xa0 {
		t.Errorf("[0] EXPLICIT tag = 0x%02x, want 0xa0", got[0])
	}
}

func TestAsn1WrapExplicit_Tag2(t *testing.T) {
	content := []byte{0xdd}
	got := asn1WrapExplicit(2, content)
	// [2] EXPLICIT = 0xa2
	if got[0] != 0xa2 {
		t.Errorf("[2] EXPLICIT tag = 0x%02x, want 0xa2", got[0])
	}
}

func TestAsn1WrapApplication_Tag(t *testing.T) {
	content := []byte{0xee}
	got := asn1WrapApplication(0, content)
	// APPLICATION [0] = 0x60
	if got[0] != 0x60 {
		t.Errorf("APPLICATION [0] tag = 0x%02x, want 0x60", got[0])
	}
}

func TestAsn1WrapContextTag_Tag1(t *testing.T) {
	content := []byte{0xff}
	got := asn1WrapContextTag(1, content)
	// [1] CONSTRUCTED = 0xa1
	if got[0] != 0xa1 {
		t.Errorf("[1] CONSTRUCTED tag = 0x%02x, want 0xa1", got[0])
	}
}

// --- relayNTLMValidate tests ---

func TestRelayNTLMValidate_Valid(t *testing.T) {
	msg := buildNTLMHeader(ntlmTypeNegotiate)
	if err := relayNTLMValidate(msg, ntlmTypeNegotiate); err != nil {
		t.Errorf("valid message: unexpected error: %v", err)
	}
}

func TestRelayNTLMValidate_TooShort(t *testing.T) {
	if err := relayNTLMValidate([]byte{1, 2, 3}, 1); err == nil {
		t.Error("too-short message should return error")
	}
}

func TestRelayNTLMValidate_BadSignature(t *testing.T) {
	msg := make([]byte, 12)
	copy(msg, []byte("BADNTLMSSP\x00"))
	binary.LittleEndian.PutUint32(msg[8:], ntlmTypeNegotiate)
	if err := relayNTLMValidate(msg, ntlmTypeNegotiate); err == nil {
		t.Error("bad signature should return error")
	}
}

func TestRelayNTLMValidate_WrongType(t *testing.T) {
	msg := buildNTLMHeader(ntlmTypeChallenge)
	if err := relayNTLMValidate(msg, ntlmTypeNegotiate); err == nil {
		t.Error("wrong type should return error")
	}
	if err := relayNTLMValidate(msg, ntlmTypeNegotiate); !strings.Contains(err.Error(), "expected") {
		t.Errorf("wrong type error should mention 'expected', got: %v", err)
	}
}

// --- relayNTLMType tests ---

func TestRelayNTLMType_Negotiate(t *testing.T) {
	msg := buildNTLMHeader(ntlmTypeNegotiate)
	if got := relayNTLMType(msg); got != ntlmTypeNegotiate {
		t.Errorf("type = %d, want %d", got, ntlmTypeNegotiate)
	}
}

func TestRelayNTLMType_Challenge(t *testing.T) {
	msg := buildNTLMHeader(ntlmTypeChallenge)
	if got := relayNTLMType(msg); got != ntlmTypeChallenge {
		t.Errorf("type = %d, want %d", got, ntlmTypeChallenge)
	}
}

func TestRelayNTLMType_TooShort(t *testing.T) {
	if got := relayNTLMType([]byte{1, 2}); got != 0 {
		t.Errorf("short msg type = %d, want 0", got)
	}
}

func TestRelayNTLMType_BadSignature(t *testing.T) {
	msg := make([]byte, 12)
	copy(msg, "INVALID\x00")
	binary.LittleEndian.PutUint32(msg[8:], 1)
	if got := relayNTLMType(msg); got != 0 {
		t.Errorf("bad sig type = %d, want 0", got)
	}
}

// --- readSecBuf tests ---

func TestReadSecBuf_Valid(t *testing.T) {
	buf := make([]byte, 12)
	binary.LittleEndian.PutUint16(buf[0:], 50)   // length
	binary.LittleEndian.PutUint16(buf[2:], 50)   // maxLength
	binary.LittleEndian.PutUint32(buf[4:], 100)  // offset
	sb := readSecBuf(buf, 0)
	if sb.Length != 50 {
		t.Errorf("Length = %d, want 50", sb.Length)
	}
	if sb.Offset != 100 {
		t.Errorf("Offset = %d, want 100", sb.Offset)
	}
}

func TestReadSecBuf_TooShort(t *testing.T) {
	buf := make([]byte, 4)
	sb := readSecBuf(buf, 0)
	if sb.Length != 0 && sb.Offset != 0 {
		t.Error("short buffer should return zero SecBuf")
	}
}

func TestSecBufGetData_Valid(t *testing.T) {
	msg := []byte("NTLMSSP\x00XXXX__DATA__")
	sb := relayNTLMSecBuf{Length: 6, MaxLength: 6, Offset: 12}
	got := sb.getData(msg)
	if string(got) != "__DATA" {
		t.Errorf("getData = %q, want __DATA", got)
	}
}

func TestSecBufGetData_ZeroLength(t *testing.T) {
	msg := []byte("NTLMSSP\x00XXXX")
	sb := relayNTLMSecBuf{Length: 0, MaxLength: 0, Offset: 0}
	got := sb.getData(msg)
	if got != nil {
		t.Error("zero length should return nil")
	}
}

func TestSecBufGetData_OutOfBounds(t *testing.T) {
	msg := []byte("short")
	sb := relayNTLMSecBuf{Length: 10, MaxLength: 10, Offset: 100}
	got := sb.getData(msg)
	if got != nil {
		t.Error("out-of-bounds should return nil")
	}
}

// --- relayExtractType2Challenge tests ---

func TestRelayExtractType2Challenge_Valid(t *testing.T) {
	// Build a minimal Type 2 message (32 bytes minimum)
	msg := make([]byte, 56)
	copy(msg[0:8], sniffNTLMSig)
	binary.LittleEndian.PutUint32(msg[8:], ntlmTypeChallenge)
	// Challenge at bytes 24-31
	challenge := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	copy(msg[24:32], challenge)

	got := relayExtractType2Challenge(msg)
	if !bytes.Equal(got, challenge) {
		t.Errorf("challenge = %v, want %v", got, challenge)
	}
}

func TestRelayExtractType2Challenge_TooShort(t *testing.T) {
	msg := make([]byte, 20)
	copy(msg[0:8], sniffNTLMSig)
	binary.LittleEndian.PutUint32(msg[8:], ntlmTypeChallenge)
	got := relayExtractType2Challenge(msg)
	if got != nil {
		t.Error("too-short message should return nil")
	}
}

func TestRelayExtractType2Challenge_WrongType(t *testing.T) {
	msg := make([]byte, 40)
	copy(msg[0:8], sniffNTLMSig)
	binary.LittleEndian.PutUint32(msg[8:], ntlmTypeNegotiate) // wrong type
	got := relayExtractType2Challenge(msg)
	if got != nil {
		t.Error("wrong type should return nil")
	}
}

// --- spnegoExtractNTLMToken tests ---

func TestSpnegoExtractNTLMToken_WithSignature(t *testing.T) {
	// Pad + NTLM message
	prefix := []byte{0xa1, 0x82, 0x01, 0x23}
	ntlmMsg := buildNTLMHeader(ntlmTypeChallenge)
	ntlmMsg = append(ntlmMsg, make([]byte, 48)...) // pad to realistic length
	data := append(prefix, ntlmMsg...)

	got := spnegoExtractNTLMToken(data)
	if got == nil {
		t.Fatal("expected non-nil NTLM token")
	}
	if !bytes.HasPrefix(got, sniffNTLMSig) {
		t.Errorf("extracted token doesn't start with NTLMSSP signature")
	}
}

func TestSpnegoExtractNTLMToken_NoSignature(t *testing.T) {
	data := []byte{0xa1, 0x82, 0x01, 0x23, 0x00, 0x00, 0x00}
	got := spnegoExtractNTLMToken(data)
	if got != nil {
		t.Error("no NTLMSSP signature should return nil")
	}
}

func TestSpnegoExtractNTLMToken_Empty(t *testing.T) {
	got := spnegoExtractNTLMToken(nil)
	if got != nil {
		t.Error("nil input should return nil")
	}
}

// --- spnegoWrapNegTokenInit / spnegoWrapNegTokenResp roundtrip tests ---

func TestSpnegoWrapNegTokenInit_ContainsNTLM(t *testing.T) {
	ntlmType1 := buildNTLMHeader(ntlmTypeNegotiate)
	wrapped := spnegoWrapNegTokenInit(ntlmType1)
	if wrapped == nil {
		t.Fatal("expected non-nil wrapped token")
	}
	// Should contain the NTLM negotiate message
	if !bytes.Contains(wrapped, ntlmType1) {
		t.Error("wrapped token should contain the NTLM Type 1 message")
	}
	// Should start with APPLICATION tag (0x60)
	if wrapped[0] != 0x60 {
		t.Errorf("outer tag = 0x%02x, want 0x60 (APPLICATION)", wrapped[0])
	}
	// Must contain the SPNEGO OID (1.3.6.1.5.5.2) for SMB compatibility
	if !bytes.Contains(wrapped, spnegoOID) {
		t.Error("wrapped token must contain SPNEGO OID for SMB SESSION_SETUP")
	}
}

func TestSpnegoWrapNegTokenResp_ContainsNTLM(t *testing.T) {
	ntlmType3 := buildNTLMHeader(ntlmTypeAuthenticate)
	wrapped := spnegoWrapNegTokenResp(ntlmType3)
	if wrapped == nil {
		t.Fatal("expected non-nil wrapped token")
	}
	// Should contain the NTLM authenticate message
	if !bytes.Contains(wrapped, ntlmType3) {
		t.Error("wrapped token should contain the NTLM Type 3 message")
	}
	// Should start with [1] CONSTRUCTED context tag (0xa1)
	if wrapped[0] != 0xa1 {
		t.Errorf("outer tag = 0x%02x, want 0xa1 ([1] CONSTRUCTED)", wrapped[0])
	}
}

func TestSpnegoWrapAndExtract_Roundtrip(t *testing.T) {
	ntlmType3 := buildNTLMHeader(ntlmTypeAuthenticate)
	ntlmType3 = append(ntlmType3, make([]byte, 40)...)
	wrapped := spnegoWrapNegTokenResp(ntlmType3)
	extracted := spnegoExtractNTLMToken(wrapped)
	if extracted == nil {
		t.Fatal("should be able to extract NTLM token from wrapped response")
	}
	if !bytes.HasPrefix(extracted, sniffNTLMSig) {
		t.Error("extracted token should start with NTLMSSP signature")
	}
}
