package commands

import (
	"encoding/binary"
	"encoding/hex"
	"net"
	"testing"
	"unicode/utf16"
)

func TestParsePoisonProtocols(t *testing.T) {
	tests := []struct {
		input    string
		expected map[string]bool
	}{
		{"", map[string]bool{"llmnr": true, "nbtns": true}},
		{"llmnr", map[string]bool{"llmnr": true}},
		{"nbtns", map[string]bool{"nbtns": true}},
		{"mdns", map[string]bool{"mdns": true}},
		{"llmnr,nbtns", map[string]bool{"llmnr": true, "nbtns": true}},
		{"LLMNR,NBTNS,MDNS", map[string]bool{"llmnr": true, "nbtns": true, "mdns": true}},
		{"invalid", map[string]bool{"llmnr": true, "nbtns": true}}, // defaults
		{"llmnr, nbtns", map[string]bool{"llmnr": true, "nbtns": true}}, // with spaces
	}

	for _, tc := range tests {
		result := parsePoisonProtocols(tc.input)
		if len(result) != len(tc.expected) {
			t.Errorf("parsePoisonProtocols(%q) got %v, expected %v", tc.input, result, tc.expected)
			continue
		}
		for k := range tc.expected {
			if !result[k] {
				t.Errorf("parsePoisonProtocols(%q) missing protocol %q", tc.input, k)
			}
		}
	}
}

func TestExtractLLMNRQueryName(t *testing.T) {
	tests := []struct {
		name     string
		packet   []byte
		expected string
	}{
		{
			"valid LLMNR query for WPAD",
			buildTestLLMNRQuery("WPAD"),
			"WPAD",
		},
		{
			"valid LLMNR query for fileserver",
			buildTestLLMNRQuery("fileserver"),
			"fileserver",
		},
		{
			"too short",
			[]byte{0x00, 0x01},
			"",
		},
		{
			"empty name",
			make([]byte, 13),
			"",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := extractLLMNRQueryName(tc.packet)
			if result != tc.expected {
				t.Errorf("extractLLMNRQueryName() = %q, expected %q", result, tc.expected)
			}
		})
	}
}

func TestExtractNBTNSQueryName(t *testing.T) {
	tests := []struct {
		name     string
		packet   []byte
		expected string
	}{
		{
			"valid NBT-NS query for WPAD",
			buildTestNBTNSQuery("WPAD"),
			"WPAD",
		},
		{
			"too short",
			[]byte{0x00},
			"",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := extractNBTNSQueryName(tc.packet)
			if result != tc.expected {
				t.Errorf("extractNBTNSQueryName() = %q, expected %q", result, tc.expected)
			}
		})
	}
}

func TestBuildLLMNRResponse(t *testing.T) {
	query := buildTestLLMNRQuery("WPAD")
	responseIP := net.ParseIP("10.0.0.5")

	resp, err := buildLLMNRResponse(query, responseIP)
	if err != nil {
		t.Fatalf("buildLLMNRResponse() error: %v", err)
	}

	// Check transaction ID matches
	if resp[0] != query[0] || resp[1] != query[1] {
		t.Error("Transaction ID mismatch")
	}

	// Check QR flag is set (response)
	if resp[2]&0x80 == 0 {
		t.Error("QR flag not set in response")
	}

	// Check ANCOUNT = 1
	if resp[6] != 0 || resp[7] != 1 {
		t.Error("ANCOUNT should be 1")
	}

	// Check response contains our IP
	found := false
	for i := 0; i <= len(resp)-4; i++ {
		if resp[i] == 10 && resp[i+1] == 0 && resp[i+2] == 0 && resp[i+3] == 5 {
			found = true
			break
		}
	}
	if !found {
		t.Error("Response IP 10.0.0.5 not found in response")
	}
}

func TestBuildNBTNSResponse(t *testing.T) {
	query := buildTestNBTNSQuery("WPAD")
	responseIP := net.ParseIP("192.168.1.100")

	resp, err := buildNBTNSResponse(query, responseIP)
	if err != nil {
		t.Fatalf("buildNBTNSResponse() error: %v", err)
	}

	// Check QR flag is set
	if resp[2]&0x80 == 0 {
		t.Error("QR flag not set in response")
	}

	// Check response contains our IP
	ip := responseIP.To4()
	found := false
	for i := 0; i <= len(resp)-4; i++ {
		if resp[i] == ip[0] && resp[i+1] == ip[1] && resp[i+2] == ip[2] && resp[i+3] == ip[3] {
			found = true
			break
		}
	}
	if !found {
		t.Error("Response IP not found in NBT-NS response")
	}
}

func TestBuildLLMNRResponseErrors(t *testing.T) {
	// Too short
	_, err := buildLLMNRResponse([]byte{0x00}, net.ParseIP("10.0.0.1"))
	if err == nil {
		t.Error("Expected error for short packet")
	}

	// IPv6 not supported
	query := buildTestLLMNRQuery("test")
	_, err = buildLLMNRResponse(query, net.ParseIP("::1"))
	if err == nil {
		t.Error("Expected error for IPv6")
	}
}

// Helper: build a test LLMNR query packet
func buildTestLLMNRQuery(name string) []byte {
	packet := make([]byte, 0, 64)
	// Header: TX ID, Flags=0 (query), QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0
	packet = append(packet, 0xAB, 0xCD) // TX ID
	packet = append(packet, 0x00, 0x00) // Flags: query
	packet = append(packet, 0x00, 0x01) // QDCOUNT=1
	packet = append(packet, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00) // AN/NS/AR=0
	// Question: name
	packet = append(packet, byte(len(name)))
	packet = append(packet, []byte(name)...)
	packet = append(packet, 0x00)       // null terminator
	packet = append(packet, 0x00, 0x01) // QTYPE A
	packet = append(packet, 0x00, 0x01) // QCLASS IN
	return packet
}

// Helper: build a test NBT-NS query packet
func buildTestNBTNSQuery(name string) []byte {
	packet := make([]byte, 0, 64)
	// Header
	packet = append(packet, 0xAB, 0xCD) // TX ID
	packet = append(packet, 0x01, 0x10) // Flags: query, broadcast
	packet = append(packet, 0x00, 0x01) // QDCOUNT=1
	packet = append(packet, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
	// Encode name in NetBIOS format (pad to 16 chars with spaces, then encode)
	padded := make([]byte, 16)
	copy(padded, []byte(name))
	for i := len(name); i < 16; i++ {
		padded[i] = 0x20 // space padding
	}
	packet = append(packet, 32) // label length = 32
	for _, ch := range padded {
		packet = append(packet, 'A'+(ch>>4), 'A'+(ch&0x0F))
	}
	packet = append(packet, 0x00)       // null terminator
	packet = append(packet, 0x00, 0x20) // QTYPE NB
	packet = append(packet, 0x00, 0x01) // QCLASS IN
	return packet
}

// === NTLM Type 2 / Type 3 Tests ===

func TestBuildNTLMType2(t *testing.T) {
	challenge := [8]byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF}
	type2 := buildNTLMType2(challenge)

	// Verify NTLMSSP signature
	if string(type2[0:7]) != "NTLMSSP" || type2[7] != 0x00 {
		t.Error("Invalid NTLMSSP signature")
	}

	// Verify message type = 2
	msgType := binary.LittleEndian.Uint32(type2[8:12])
	if msgType != 2 {
		t.Errorf("Expected message type 2, got %d", msgType)
	}

	// Verify challenge bytes
	for i := 0; i < 8; i++ {
		if type2[24+i] != challenge[i] {
			t.Errorf("Challenge byte %d mismatch: got 0x%02X, expected 0x%02X",
				i, type2[24+i], challenge[i])
		}
	}

	// Verify minimum length
	if len(type2) < 56 {
		t.Errorf("Type 2 too short: %d bytes", len(type2))
	}
}

func TestExtractNTLMv2Hash(t *testing.T) {
	challenge := [8]byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}

	// Build a realistic NTLM Type 3 message
	type3 := buildTestNTLMType3("TESTDOMAIN", "testuser", "WORKSTATION",
		[]byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11,
			0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99}, // NTProofStr (16 bytes)
		[]byte{0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, // client blob
	)

	hash := extractNTLMv2Hash(type3, challenge)
	if hash == nil {
		t.Fatal("extractNTLMv2Hash returned nil")
	}

	if hash.Username != "testuser" {
		t.Errorf("Username = %q, expected 'testuser'", hash.Username)
	}
	if hash.Domain != "TESTDOMAIN" {
		t.Errorf("Domain = %q, expected 'TESTDOMAIN'", hash.Domain)
	}
	if hash.ServerChallenge != hex.EncodeToString(challenge[:]) {
		t.Errorf("ServerChallenge = %q, expected %q",
			hash.ServerChallenge, hex.EncodeToString(challenge[:]))
	}
	if hash.NTProofStr != "aabbccddeeff00112233445566778899" {
		t.Errorf("NTProofStr = %q", hash.NTProofStr)
	}
	if hash.NTLMv2Blob != "0101000000000000" {
		t.Errorf("NTLMv2Blob = %q", hash.NTLMv2Blob)
	}

	// Verify hashcat format: user::domain:challenge:ntproofstr:blob
	expectedHashcat := "testuser::TESTDOMAIN:1122334455667788:aabbccddeeff00112233445566778899:0101000000000000"
	if hash.HashcatFormat != expectedHashcat {
		t.Errorf("HashcatFormat = %q\nexpected       %q", hash.HashcatFormat, expectedHashcat)
	}
}

func TestExtractNTLMv2HashEdgeCases(t *testing.T) {
	challenge := [8]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}

	// Too short
	if extractNTLMv2Hash(make([]byte, 20), challenge) != nil {
		t.Error("Should return nil for short data")
	}

	// Wrong signature
	bad := make([]byte, 100)
	copy(bad[0:8], []byte("WRONGSIG"))
	if extractNTLMv2Hash(bad, challenge) != nil {
		t.Error("Should return nil for wrong signature")
	}

	// Type 1 instead of Type 3
	type1 := make([]byte, 100)
	copy(type1[0:8], []byte("NTLMSSP\x00"))
	binary.LittleEndian.PutUint32(type1[8:12], 1)
	if extractNTLMv2Hash(type1, challenge) != nil {
		t.Error("Should return nil for Type 1 message")
	}

	// Type 3 with empty username
	type3empty := buildTestNTLMType3("DOMAIN", "", "HOST",
		make([]byte, 16), make([]byte, 8))
	if extractNTLMv2Hash(type3empty, challenge) != nil {
		t.Error("Should return nil for empty username")
	}
}

func TestExtractHTTPNTLMAuth(t *testing.T) {
	tests := []struct {
		name    string
		request string
		wantNil bool
	}{
		{"no auth header", "GET / HTTP/1.1\r\nHost: test\r\n\r\n", true},
		{"basic auth", "GET / HTTP/1.1\r\nAuthorization: Basic dGVzdA==\r\n\r\n", true},
		{"valid NTLM", "GET / HTTP/1.1\r\nAuthorization: NTLM TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAGAbEdAAAADw==\r\n\r\n", false},
		{"empty NTLM", "GET / HTTP/1.1\r\nAuthorization: NTLM \r\n\r\n", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := extractHTTPNTLMAuth(tc.request)
			if tc.wantNil && result != nil {
				t.Errorf("Expected nil, got %d bytes", len(result))
			}
			if !tc.wantNil && result == nil {
				t.Error("Expected non-nil result")
			}
		})
	}
}

func TestNTLMType2RoundTrip(t *testing.T) {
	// Build a Type 2 and verify it can be parsed back
	challenge := [8]byte{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE}
	type2 := buildNTLMType2(challenge)

	// Verify it starts with NTLMSSP
	if string(type2[0:7]) != "NTLMSSP" {
		t.Fatal("Not an NTLMSSP message")
	}

	// Verify negotiate flags include NTLM
	flags := binary.LittleEndian.Uint32(type2[20:24])
	if flags&0x200 == 0 {
		t.Error("NEGOTIATE_NTLM flag not set")
	}
	if flags&0x01 == 0 {
		t.Error("NEGOTIATE_UNICODE flag not set")
	}
}

// buildTestNTLMType3 constructs a minimal NTLM Type 3 message for testing.
func buildTestNTLMType3(domain, user, workstation string, ntProofStr, clientBlob []byte) []byte {
	encodeUTF16LE := func(s string) []byte {
		runes := []rune(s)
		u16 := utf16.Encode(runes)
		b := make([]byte, len(u16)*2)
		for i, v := range u16 {
			binary.LittleEndian.PutUint16(b[i*2:], v)
		}
		return b
	}

	domainBytes := encodeUTF16LE(domain)
	userBytes := encodeUTF16LE(user)
	wsBytes := encodeUTF16LE(workstation)

	// NtChallengeResponse = NTProofStr + client blob
	ntResponse := append(ntProofStr, clientBlob...)

	// LmChallengeResponse (24 bytes of zeros for NTLMv2)
	lmResponse := make([]byte, 24)

	// Build the Type 3 structure
	// Header: 72 bytes (NTLMSSP sig + type + 6 security buffers + flags + os version)
	headerLen := 72
	dataOffset := headerLen

	// Security buffer layout (offset, len):
	// LM Response:     offset 12
	// NT Response:     offset 20
	// Domain:          offset 28
	// User:            offset 36
	// Workstation:     offset 44
	// Encrypted RS:    offset 52 (empty)
	// Negotiate Flags: offset 60

	type3 := make([]byte, headerLen+len(lmResponse)+len(ntResponse)+len(domainBytes)+len(userBytes)+len(wsBytes))

	// NTLMSSP signature + Type 3
	copy(type3[0:8], []byte("NTLMSSP\x00"))
	binary.LittleEndian.PutUint32(type3[8:12], 3)

	writeSecBuf := func(offset, fieldOffset int, data []byte) {
		binary.LittleEndian.PutUint16(type3[offset:], uint16(len(data)))
		binary.LittleEndian.PutUint16(type3[offset+2:], uint16(len(data)))
		binary.LittleEndian.PutUint32(type3[offset+4:], uint32(fieldOffset))
		copy(type3[fieldOffset:], data)
	}

	// Pack data fields after header
	lmOff := dataOffset
	ntOff := lmOff + len(lmResponse)
	domOff := ntOff + len(ntResponse)
	userOff := domOff + len(domainBytes)
	wsOff := userOff + len(userBytes)

	writeSecBuf(12, lmOff, lmResponse)
	writeSecBuf(20, ntOff, ntResponse)
	writeSecBuf(28, domOff, domainBytes)
	writeSecBuf(36, userOff, userBytes)
	writeSecBuf(44, wsOff, wsBytes)

	// Negotiate Flags
	binary.LittleEndian.PutUint32(type3[60:64], 0x00028233)

	return type3
}
