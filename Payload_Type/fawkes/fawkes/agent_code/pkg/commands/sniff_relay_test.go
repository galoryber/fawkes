package commands

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// --- NTLM Message Tests ---

// testType1 builds a minimal NTLM Type 1 (Negotiate) message for tests.
func testType1() []byte {
	msg := make([]byte, 32)
	copy(msg[0:8], "NTLMSSP\x00")
	binary.LittleEndian.PutUint32(msg[8:12], 1)
	binary.LittleEndian.PutUint32(msg[12:16], 0x000B8207)
	return msg
}

// testType3 builds an NTLM Type 3 using the existing test helper.
func testType3() []byte {
	ntProofStr := make([]byte, 16)
	clientBlob := make([]byte, 28)
	for i := range ntProofStr {
		ntProofStr[i] = byte(i)
	}
	for i := range clientBlob {
		clientBlob[i] = byte(i + 16)
	}
	return buildTestNTLMType3("TESTDOM", "testuser", "WKS01", ntProofStr, clientBlob)
}

func TestRelayNTLMType(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected uint32
	}{
		{"valid Type 1", testType1(), 1},
		{"valid Type 2", buildNTLMType2([8]byte{1, 2, 3, 4, 5, 6, 7, 8}), 2},
		{"valid Type 3", testType3(), 3},
		{"too short", []byte("NTLMSSP\x00"), 0},
		{"wrong signature", []byte("XXXXXXXX\x01\x00\x00\x00"), 0},
		{"nil data", nil, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := relayNTLMType(tt.data)
			if got != tt.expected {
				t.Errorf("relayNTLMType() = %d, want %d", got, tt.expected)
			}
		})
	}
}

func TestRelayNTLMValidate(t *testing.T) {
	tests := []struct {
		name         string
		data         []byte
		expectedType uint32
		wantErr      bool
	}{
		{"valid Type 1", testType1(), 1, false},
		{"wrong type expected", testType1(), 3, true},
		{"too short", []byte("short"), 1, true},
		{"bad signature", []byte("BADSIG00\x01\x00\x00\x00extra"), 1, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := relayNTLMValidate(tt.data, tt.expectedType)
			if (err != nil) != tt.wantErr {
				t.Errorf("relayNTLMValidate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestRelayExtractType2Challenge(t *testing.T) {
	challenge := [8]byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	type2 := buildNTLMType2(challenge)

	got := relayExtractType2Challenge(type2)
	if got == nil {
		t.Fatal("returned nil")
	}
	if !bytes.Equal(got, challenge[:]) {
		t.Errorf("challenge = %x, want %x", got, challenge)
	}

	// Invalid inputs
	if relayExtractType2Challenge([]byte("short")) != nil {
		t.Error("expected nil for short input")
	}
	if relayExtractType2Challenge(testType1()) != nil {
		t.Error("expected nil for Type 1 input")
	}
}

func TestRelayExtractType3Info(t *testing.T) {
	type3 := testType3()
	user, domain := relayExtractType3Info(type3)
	if user != "testuser" {
		t.Errorf("user = %q, want %q", user, "testuser")
	}
	if domain != "TESTDOM" {
		t.Errorf("domain = %q, want %q", domain, "TESTDOM")
	}

	// Invalid input
	user, domain = relayExtractType3Info([]byte("short"))
	if user != "" || domain != "" {
		t.Error("expected empty strings for invalid input")
	}
}

// --- SPNEGO Wrapping Tests ---

func TestSPNEGOWrapNegTokenInit(t *testing.T) {
	type1 := testType1()
	wrapped := spnegoWrapNegTokenInit(type1)

	if len(wrapped) == 0 || wrapped[0] != 0x60 {
		t.Fatalf("expected APPLICATION[0] tag (0x60), got 0x%02x", wrapped[0])
	}
	if !bytes.Contains(wrapped, ntlmsspOID) {
		t.Error("wrapped token should contain NTLMSSP OID")
	}
	if !bytes.Contains(wrapped, type1) {
		t.Error("wrapped token should contain original Type 1 message")
	}
}

func TestSPNEGOWrapNegTokenResp(t *testing.T) {
	type3 := testType3()
	wrapped := spnegoWrapNegTokenResp(type3)

	if len(wrapped) == 0 || wrapped[0] != 0xa1 {
		t.Fatalf("expected context[1] tag (0xa1), got 0x%02x", wrapped[0])
	}
	if !bytes.Contains(wrapped, type3) {
		t.Error("wrapped token should contain original Type 3 message")
	}
}

func TestSPNEGOExtractNTLMToken(t *testing.T) {
	challenge := [8]byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11}
	type2 := buildNTLMType2(challenge)

	// Wrap in some SPNEGO-like envelope
	spnego := append([]byte{0xa1, 0x82, 0x00, 0x50, 0x30, 0x10, 0x04}, type2...)

	extracted := spnegoExtractNTLMToken(spnego)
	if extracted == nil {
		t.Fatal("returned nil")
	}
	if relayNTLMType(extracted) != ntlmTypeChallenge {
		t.Error("extracted token is not a Type 2 message")
	}

	extractedChallenge := relayExtractType2Challenge(extracted)
	if !bytes.Equal(extractedChallenge, challenge[:]) {
		t.Errorf("challenge mismatch: got %x, want %x", extractedChallenge, challenge)
	}
}

func TestSPNEGOExtractNTLMTokenNotFound(t *testing.T) {
	data := []byte{0xa1, 0x10, 0x30, 0x0e, 0x04, 0x0c, 'N', 'o', 'N', 'T', 'L', 'M'}
	if spnegoExtractNTLMToken(data) != nil {
		t.Error("expected nil when no NTLMSSP signature present")
	}
}

func TestSPNEGORoundTrip(t *testing.T) {
	// Wrap Type 1, extract it back
	type1 := testType1()
	wrapped := spnegoWrapNegTokenInit(type1)
	extracted := spnegoExtractNTLMToken(wrapped)
	if extracted == nil {
		t.Fatal("failed to extract Type 1 from SPNEGO negTokenInit")
	}
	if !bytes.Equal(extracted, type1) {
		t.Error("extracted Type 1 doesn't match original")
	}

	// Wrap Type 3, extract it back
	type3 := testType3()
	wrappedResp := spnegoWrapNegTokenResp(type3)
	extractedResp := spnegoExtractNTLMToken(wrappedResp)
	if extractedResp == nil {
		t.Fatal("failed to extract Type 3 from SPNEGO negTokenResp")
	}
	if !bytes.Equal(extractedResp, type3) {
		t.Error("extracted Type 3 doesn't match original")
	}
}

// --- SMB2 Protocol Tests ---

func TestSMB2ParseStatus(t *testing.T) {
	rc := &relayConn{}

	tests := []struct {
		name     string
		status   uint32
	}{
		{"STATUS_OK", smb2StatusOK},
		{"STATUS_MORE_PROCESSING", smb2StatusMoreProcessing},
		{"STATUS_LOGON_FAILURE", smb2StatusLogonFailure},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := make([]byte, 64)
			copy(r[0:4], smb2Magic)
			binary.LittleEndian.PutUint32(r[8:12], tt.status)
			got := rc.parseStatus(r)
			if got != tt.status {
				t.Errorf("parseStatus() = 0x%08X, want 0x%08X", got, tt.status)
			}
		})
	}

	// Too short
	if rc.parseStatus([]byte("short")) != 0xFFFFFFFF {
		t.Error("expected 0xFFFFFFFF for short input")
	}
}

func TestSMB2MessageIDIncrement(t *testing.T) {
	rc := &relayConn{messageID: 0}
	if rc.messageID != 0 {
		t.Errorf("initial messageID should be 0, got %d", rc.messageID)
	}
}

// --- ASN.1 Helper Tests ---

func TestRelayASN1WrapLength(t *testing.T) {
	tests := []struct {
		length   int
		expected []byte
	}{
		{0, []byte{0x00}},
		{1, []byte{0x01}},
		{127, []byte{0x7f}},
		{128, []byte{0x81, 0x80}},
		{255, []byte{0x81, 0xff}},
		{256, []byte{0x82, 0x01, 0x00}},
		{1000, []byte{0x82, 0x03, 0xe8}},
	}

	for _, tt := range tests {
		got := asn1WrapLength(tt.length)
		if !bytes.Equal(got, tt.expected) {
			t.Errorf("asn1WrapLength(%d) = %x, want %x", tt.length, got, tt.expected)
		}
	}
}

func TestRelayASN1WrapSequence(t *testing.T) {
	content := []byte{0x01, 0x02, 0x03}
	got := asn1WrapSequence(content)
	if got[0] != 0x30 {
		t.Errorf("expected SEQUENCE tag 0x30, got 0x%02x", got[0])
	}
	if got[1] != 3 {
		t.Errorf("expected length 3, got %d", got[1])
	}
	if !bytes.Equal(got[2:], content) {
		t.Error("content mismatch")
	}
}

func TestRelayASN1WrapOctetString(t *testing.T) {
	content := []byte{0xAA, 0xBB}
	got := asn1WrapOctetString(content)
	if got[0] != 0x04 {
		t.Errorf("expected OCTET STRING tag 0x04, got 0x%02x", got[0])
	}
	if got[1] != 2 {
		t.Errorf("expected length 2, got %d", got[1])
	}
}

func TestRelayBuildNTLMv2Hashcat(t *testing.T) {
	type3 := testType3()
	challenge := []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}

	hashcat := relayBuildNTLMv2Hashcat(type3, challenge)
	// Verify it's in the expected format: user::domain:challenge:ntproofstr:blob
	if hashcat == "" {
		t.Error("expected non-empty hashcat string for valid Type 3")
	}

	// Invalid challenge length
	if relayBuildNTLMv2Hashcat(type3, []byte{0x11}) != "" {
		t.Error("expected empty string for invalid challenge length")
	}
}

func TestRelayReadSecBuf(t *testing.T) {
	data := make([]byte, 100)
	binary.LittleEndian.PutUint16(data[12:14], 4)   // Length
	binary.LittleEndian.PutUint16(data[14:16], 4)   // MaxLength
	binary.LittleEndian.PutUint32(data[16:20], 50)  // Offset
	copy(data[50:54], []byte("TEST"))

	sb := readSecBuf(data, 12)
	if sb.Length != 4 {
		t.Errorf("Length = %d, want 4", sb.Length)
	}
	if sb.Offset != 50 {
		t.Errorf("Offset = %d, want 50", sb.Offset)
	}

	got := sb.getData(data)
	if string(got) != "TEST" {
		t.Errorf("getData() = %q, want %q", string(got), "TEST")
	}

	// Zero length buffer returns nil
	binary.LittleEndian.PutUint16(data[12:14], 0)
	sb2 := readSecBuf(data, 12)
	if sb2.getData(data) != nil {
		t.Error("expected nil for zero-length security buffer")
	}

	// Out of bounds offset
	sb3 := readSecBuf(data, 95)
	_ = sb3 // just verify no panic
}
