package commands

import (
	"encoding/binary"
	"testing"
	"unicode/utf16"
)

func TestSniffDecodeUTF16LE_Basic(t *testing.T) {
	input := sniffUTF16LEEncode("hello")
	got := sniffDecodeUTF16LE(input)
	if got != "hello" {
		t.Errorf("expected 'hello', got %q", got)
	}
}

func TestSniffDecodeUTF16LE_Empty(t *testing.T) {
	if sniffDecodeUTF16LE(nil) != "" {
		t.Error("nil should return empty")
	}
	if sniffDecodeUTF16LE([]byte{}) != "" {
		t.Error("empty should return empty")
	}
}

func TestSniffDecodeUTF16LE_OddLength(t *testing.T) {
	if sniffDecodeUTF16LE([]byte{0x41}) != "" {
		t.Error("odd-length should return empty")
	}
}

func TestSniffDecodeUTF16LE_Unicode(t *testing.T) {
	input := sniffUTF16LEEncode("DOMAIN")
	got := sniffDecodeUTF16LE(input)
	if got != "DOMAIN" {
		t.Errorf("expected 'DOMAIN', got %q", got)
	}
}

func TestSniffExtractHTTPBasicAuth_Valid(t *testing.T) {
	payload := []byte("GET /api HTTP/1.1\r\nHost: example.com\r\nAuthorization: Basic YWRtaW46cGFzc3dvcmQ=\r\n\r\n")
	meta := &packetMeta{SrcIP: "10.0.0.1", SrcPort: 12345, DstIP: "10.0.0.2", DstPort: 80}

	cred := sniffExtractHTTPBasicAuth(payload, meta)
	if cred == nil {
		t.Fatal("expected credential, got nil")
	}
	if cred.Username != "admin" {
		t.Errorf("username = %q, want 'admin'", cred.Username)
	}
	if cred.Password != "password" {
		t.Errorf("password = %q, want 'password'", cred.Password)
	}
	if cred.Protocol != "http-basic" {
		t.Errorf("protocol = %q, want 'http-basic'", cred.Protocol)
	}
	if cred.SrcIP != "10.0.0.1" {
		t.Errorf("srcIP = %q", cred.SrcIP)
	}
}

func TestSniffExtractHTTPBasicAuth_POST(t *testing.T) {
	payload := []byte("POST /login HTTP/1.1\r\nAuthorization: Basic dXNlcjpzZWNyZXQ=\r\n\r\n")
	meta := &packetMeta{SrcIP: "10.0.0.1", SrcPort: 12345, DstIP: "10.0.0.2", DstPort: 80}

	cred := sniffExtractHTTPBasicAuth(payload, meta)
	if cred == nil {
		t.Fatal("expected credential")
	}
	if cred.Username != "user" || cred.Password != "secret" {
		t.Errorf("got user=%q pass=%q", cred.Username, cred.Password)
	}
}

func TestSniffExtractHTTPBasicAuth_NoAuth(t *testing.T) {
	payload := []byte("GET /api HTTP/1.1\r\nHost: example.com\r\n\r\n")
	meta := &packetMeta{SrcIP: "10.0.0.1", SrcPort: 12345, DstIP: "10.0.0.2", DstPort: 80}

	if sniffExtractHTTPBasicAuth(payload, meta) != nil {
		t.Error("no auth header should return nil")
	}
}

func TestSniffExtractHTTPBasicAuth_InvalidBase64(t *testing.T) {
	payload := []byte("GET /api HTTP/1.1\r\nAuthorization: Basic not-valid-b64!!!\r\n\r\n")
	meta := &packetMeta{SrcIP: "10.0.0.1", SrcPort: 12345, DstIP: "10.0.0.2", DstPort: 80}

	if sniffExtractHTTPBasicAuth(payload, meta) != nil {
		t.Error("invalid base64 should return nil")
	}
}

func TestSniffExtractHTTPBasicAuth_ShortPayload(t *testing.T) {
	meta := &packetMeta{SrcIP: "10.0.0.1", SrcPort: 12345, DstIP: "10.0.0.2", DstPort: 80}

	if sniffExtractHTTPBasicAuth([]byte("GE"), meta) != nil {
		t.Error("short payload should return nil")
	}
	if sniffExtractHTTPBasicAuth(nil, meta) != nil {
		t.Error("nil payload should return nil")
	}
}

func TestSniffExtractHTTPBasicAuth_NonHTTPVerb(t *testing.T) {
	payload := []byte("XPOST /api HTTP/1.1\r\nAuthorization: Basic YWRtaW46cGFzcw==\r\n\r\n")
	meta := &packetMeta{SrcIP: "10.0.0.1", SrcPort: 12345, DstIP: "10.0.0.2", DstPort: 80}

	if sniffExtractHTTPBasicAuth(payload, meta) != nil {
		t.Error("non-HTTP verb prefix should return nil")
	}
}

func TestSniffExtractHTTPBasicAuth_CaseInsensitive(t *testing.T) {
	payload := []byte("GET /api HTTP/1.1\r\nAUTHORIZATION: BASIC YWRtaW46cGFzcw==\r\n\r\n")
	meta := &packetMeta{SrcIP: "10.0.0.1", SrcPort: 12345, DstIP: "10.0.0.2", DstPort: 80}

	cred := sniffExtractHTTPBasicAuth(payload, meta)
	if cred == nil {
		t.Fatal("case-insensitive header should be found")
	}
	if cred.Username != "admin" || cred.Password != "pass" {
		t.Errorf("got user=%q pass=%q", cred.Username, cred.Password)
	}
}

func TestSniffExtractHTTPBasicAuth_NoColon(t *testing.T) {
	// base64 of "justusernopass" (no colon separator)
	payload := []byte("GET / HTTP/1.1\r\nAuthorization: Basic anVzdHVzZXJub3Bhc3M=\r\n\r\n")
	meta := &packetMeta{SrcIP: "10.0.0.1", SrcPort: 12345, DstIP: "10.0.0.2", DstPort: 80}

	if sniffExtractHTTPBasicAuth(payload, meta) != nil {
		t.Error("no colon in decoded value should return nil")
	}
}

func TestSniffFTPTracker_UserThenPass(t *testing.T) {
	ft := &sniffFTPTracker{pending: make(map[string]string)}
	meta := &packetMeta{SrcIP: "10.0.0.1", SrcPort: 12345, DstIP: "10.0.0.2", DstPort: 21}

	cred := ft.process([]byte("USER ftpuser\r\n"), meta)
	if cred != nil {
		t.Error("USER alone should not produce credential")
	}

	cred = ft.process([]byte("PASS ftppass\r\n"), meta)
	if cred == nil {
		t.Fatal("PASS after USER should produce credential")
	}
	if cred.Username != "ftpuser" || cred.Password != "ftppass" {
		t.Errorf("got user=%q pass=%q", cred.Username, cred.Password)
	}
	if cred.Protocol != "ftp" {
		t.Errorf("protocol = %q", cred.Protocol)
	}
}

func TestSniffFTPTracker_PassWithoutUser(t *testing.T) {
	ft := &sniffFTPTracker{pending: make(map[string]string)}
	meta := &packetMeta{SrcIP: "10.0.0.1", SrcPort: 12345, DstIP: "10.0.0.2", DstPort: 21}

	cred := ft.process([]byte("PASS orphanpass\r\n"), meta)
	if cred != nil {
		t.Error("PASS without preceding USER should return nil")
	}
}

func TestSniffFTPTracker_AnonymousSkipped(t *testing.T) {
	ft := &sniffFTPTracker{pending: make(map[string]string)}
	meta := &packetMeta{SrcIP: "10.0.0.1", SrcPort: 12345, DstIP: "10.0.0.2", DstPort: 21}

	ft.process([]byte("USER anonymous\r\n"), meta)
	cred := ft.process([]byte("PASS test@test.com\r\n"), meta)
	if cred != nil {
		t.Error("anonymous user should be skipped")
	}
}

func TestSniffFTPTracker_CaseInsensitive(t *testing.T) {
	ft := &sniffFTPTracker{pending: make(map[string]string)}
	meta := &packetMeta{SrcIP: "10.0.0.1", SrcPort: 12345, DstIP: "10.0.0.2", DstPort: 21}

	ft.process([]byte("user admin\r\n"), meta)
	cred := ft.process([]byte("pass secret\r\n"), meta)
	if cred == nil {
		t.Fatal("case-insensitive USER/PASS should work")
	}
	if cred.Username != "admin" {
		t.Errorf("username = %q", cred.Username)
	}
}

func TestSniffFTPTracker_EmptyPayload(t *testing.T) {
	ft := &sniffFTPTracker{pending: make(map[string]string)}
	meta := &packetMeta{SrcIP: "10.0.0.1", SrcPort: 12345, DstIP: "10.0.0.2", DstPort: 21}

	if ft.process([]byte(""), meta) != nil {
		t.Error("empty payload should return nil")
	}
}

func TestSniffExtractNTLM_Type3(t *testing.T) {
	// Build a minimal NTLM Type 3 message
	msg := buildNTLMType3("TESTDOMAIN", "testuser", "WORKSTATION")
	meta := &packetMeta{SrcIP: "10.0.0.1", SrcPort: 12345, DstIP: "10.0.0.2", DstPort: 445}

	cred := sniffExtractNTLM(msg, meta)
	if cred == nil {
		t.Fatal("expected NTLM credential")
	}
	if cred.Username != "TESTDOMAIN\\testuser" {
		t.Errorf("username = %q, want 'TESTDOMAIN\\testuser'", cred.Username)
	}
	if cred.Protocol != "ntlm" {
		t.Errorf("protocol = %q", cred.Protocol)
	}
}

func TestSniffExtractNTLM_NoDomain(t *testing.T) {
	msg := buildNTLMType3("", "localuser", "PC01")
	meta := &packetMeta{SrcIP: "10.0.0.1", SrcPort: 12345, DstIP: "10.0.0.2", DstPort: 445}

	cred := sniffExtractNTLM(msg, meta)
	if cred == nil {
		t.Fatal("expected credential")
	}
	if cred.Username != "localuser" {
		t.Errorf("username = %q, want 'localuser'", cred.Username)
	}
}

func TestSniffExtractNTLM_NoSignature(t *testing.T) {
	meta := &packetMeta{SrcIP: "10.0.0.1", SrcPort: 12345, DstIP: "10.0.0.2", DstPort: 445}
	if sniffExtractNTLM([]byte("random data without NTLMSSP"), meta) != nil {
		t.Error("no NTLM signature should return nil")
	}
}

func TestSniffExtractNTLM_Type1Ignored(t *testing.T) {
	// Type 1 (Negotiate) message — should be ignored
	msg := make([]byte, 72)
	copy(msg, "NTLMSSP\x00")
	binary.LittleEndian.PutUint32(msg[8:12], 1) // Type 1
	meta := &packetMeta{SrcIP: "10.0.0.1", SrcPort: 12345, DstIP: "10.0.0.2", DstPort: 445}

	if sniffExtractNTLM(msg, meta) != nil {
		t.Error("Type 1 message should return nil")
	}
}

func TestSniffExtractNTLM_TooShort(t *testing.T) {
	msg := append([]byte("NTLMSSP\x00"), make([]byte, 10)...)
	meta := &packetMeta{SrcIP: "10.0.0.1", SrcPort: 12345, DstIP: "10.0.0.2", DstPort: 445}

	if sniffExtractNTLM(msg, meta) != nil {
		t.Error("too short NTLM message should return nil")
	}
}

func TestSniffExtractNTLM_EmptyUser(t *testing.T) {
	msg := buildNTLMType3("DOMAIN", "", "HOST")
	meta := &packetMeta{SrcIP: "10.0.0.1", SrcPort: 12345, DstIP: "10.0.0.2", DstPort: 445}

	if sniffExtractNTLM(msg, meta) != nil {
		t.Error("empty username should return nil")
	}
}

func TestSniffExtractNTLM_EmbeddedInLargerPayload(t *testing.T) {
	prefix := []byte("HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: NTLM ")
	ntlmMsg := buildNTLMType3("CORP", "admin", "PC01")
	payload := append(prefix, ntlmMsg...)
	meta := &packetMeta{SrcIP: "10.0.0.1", SrcPort: 12345, DstIP: "10.0.0.2", DstPort: 80}

	cred := sniffExtractNTLM(payload, meta)
	if cred == nil {
		t.Fatal("NTLM embedded in HTTP response should be found")
	}
	if cred.Username != "CORP\\admin" {
		t.Errorf("username = %q", cred.Username)
	}
}

// --- helpers ---

func sniffUTF16LEEncode(s string) []byte {
	runes := utf16.Encode([]rune(s))
	b := make([]byte, len(runes)*2)
	for i, r := range runes {
		binary.LittleEndian.PutUint16(b[i*2:], r)
	}
	return b
}

func buildNTLMType3(domain, user, host string) []byte {
	domainBytes := sniffUTF16LEEncode(domain)
	userBytes := sniffUTF16LEEncode(user)
	hostBytes := sniffUTF16LEEncode(host)

	// Fixed header size: 72 bytes (minimum for Type 3 with flags at offset 60)
	headerSize := 72
	dataStart := headerSize

	domainOff := dataStart
	userOff := domainOff + len(domainBytes)
	hostOff := userOff + len(userBytes)
	totalLen := hostOff + len(hostBytes)

	msg := make([]byte, totalLen)
	copy(msg[0:8], "NTLMSSP\x00")
	binary.LittleEndian.PutUint32(msg[8:12], 3) // Type 3

	// LM Response (offset 12): len=0, offset=0
	// NT Response (offset 20): len=0, offset=0

	// Domain (offset 28): len, maxlen, offset
	binary.LittleEndian.PutUint16(msg[28:30], uint16(len(domainBytes)))
	binary.LittleEndian.PutUint16(msg[30:32], uint16(len(domainBytes)))
	binary.LittleEndian.PutUint32(msg[32:36], uint32(domainOff))

	// User (offset 36): len, maxlen, offset
	binary.LittleEndian.PutUint16(msg[36:38], uint16(len(userBytes)))
	binary.LittleEndian.PutUint16(msg[38:40], uint16(len(userBytes)))
	binary.LittleEndian.PutUint32(msg[40:44], uint32(userOff))

	// Host (offset 44): len, maxlen, offset
	binary.LittleEndian.PutUint16(msg[44:46], uint16(len(hostBytes)))
	binary.LittleEndian.PutUint16(msg[46:48], uint16(len(hostBytes)))
	binary.LittleEndian.PutUint32(msg[48:52], uint32(hostOff))

	// Flags (offset 60): NTLMSSP_NEGOTIATE_UNICODE = 0x01
	binary.LittleEndian.PutUint32(msg[60:64], 0x01)

	copy(msg[domainOff:], domainBytes)
	copy(msg[userOff:], userBytes)
	copy(msg[hostOff:], hostBytes)

	return msg
}
