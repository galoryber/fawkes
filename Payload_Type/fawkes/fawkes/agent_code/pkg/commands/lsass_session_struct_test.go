package commands

import (
	"encoding/binary"
	"strings"
	"testing"
	"unicode/utf16"
)

// utf16LEBytes is a test helper that serializes a Go string as UTF-16LE
// (without trailing null) for stuffing into a synthetic remote page.
func utf16LEBytes(s string) []byte {
	enc := utf16.Encode([]rune(s))
	out := make([]byte, len(enc)*2)
	for i, c := range enc {
		binary.LittleEndian.PutUint16(out[i*2:i*2+2], c)
	}
	return out
}

// stampUnicodeStringHeader writes Length, MaxLen (= Length + 2), pad zeros,
// and Buffer pointer at `raw[at:at+16]`. Caller is responsible for
// registering the Buffer-pointer page in the test reader.
func stampUnicodeStringHeader(raw []byte, at int, lengthBytes uint16, bufferAddr uintptr) {
	binary.LittleEndian.PutUint16(raw[at:at+2], lengthBytes)
	binary.LittleEndian.PutUint16(raw[at+2:at+4], lengthBytes+2)
	binary.LittleEndian.PutUint64(raw[at+8:at+16], uint64(bufferAddr))
}

// makeFullNode builds a 0x180-byte node sized for LayoutWin10New. Optional
// fillers populate just the fields parseLogonSessionFields reads.
func makeFullNode(flink, blink uintptr, luid uint64, logonType uint32, credsPtr uintptr) []byte {
	n := make([]byte, LayoutWin10New.NodeReadSize)
	binary.LittleEndian.PutUint64(n[0:8], uint64(flink))
	binary.LittleEndian.PutUint64(n[8:16], uint64(blink))
	binary.LittleEndian.PutUint64(n[LayoutWin10New.LUIDOffset:LayoutWin10New.LUIDOffset+8], luid)
	binary.LittleEndian.PutUint32(n[LayoutWin10New.LogonTypeOffset:LayoutWin10New.LogonTypeOffset+4], logonType)
	binary.LittleEndian.PutUint64(n[LayoutWin10New.CredentialsOff:LayoutWin10New.CredentialsOff+8], uint64(credsPtr))
	return n
}

func TestParseLSAUnicodeStringHeader_Normal(t *testing.T) {
	raw := make([]byte, lsaUnicodeStringHeaderSize)
	stampUnicodeStringHeader(raw, 0, 26, 0xDEADBEEF00000010)
	length, maxLen, buf, err := parseLSAUnicodeStringHeader(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if length != 26 || maxLen != 28 || buf != 0xDEADBEEF00000010 {
		t.Errorf("got length=%d maxLen=%d buf=0x%X; want 26/28/0xDEADBEEF00000010", length, maxLen, buf)
	}
}

func TestParseLSAUnicodeStringHeader_ShortBuffer(t *testing.T) {
	_, _, _, err := parseLSAUnicodeStringHeader([]byte{1, 2, 3, 4})
	if err == nil {
		t.Fatal("expected error on short buffer")
	}
}

func TestReadLSAUnicodeString_RoundTrip(t *testing.T) {
	const userBufAddr = uintptr(0xAA0000)
	r := newBufferReader()
	r.put(userBufAddr, utf16LEBytes("Administrator"))

	raw := make([]byte, 0x100)
	const fieldOffset = 0x90
	stampUnicodeStringHeader(raw, fieldOffset, uint16(len("Administrator")*2), userBufAddr)

	got, err := readLSAUnicodeString(r, raw, fieldOffset, 1024)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "Administrator" {
		t.Errorf("got %q, want %q", got, "Administrator")
	}
}

func TestReadLSAUnicodeString_EmptyLengthZero(t *testing.T) {
	raw := make([]byte, 0x40)
	stampUnicodeStringHeader(raw, 0, 0, 0xDEAD0000)
	got, err := readLSAUnicodeString(newBufferReader(), raw, 0, 1024)
	if err != nil || got != "" {
		t.Errorf("got %q, err=%v; want empty/nil", got, err)
	}
}

func TestReadLSAUnicodeString_EmptyBufferPtr(t *testing.T) {
	raw := make([]byte, 0x40)
	stampUnicodeStringHeader(raw, 0, 8, 0)
	got, err := readLSAUnicodeString(newBufferReader(), raw, 0, 1024)
	if err != nil || got != "" {
		t.Errorf("got %q, err=%v; want empty/nil for null buffer ptr", got, err)
	}
}

func TestReadLSAUnicodeString_RejectsOddLength(t *testing.T) {
	raw := make([]byte, 0x40)
	stampUnicodeStringHeader(raw, 0, 7, 0xAA0000)
	_, err := readLSAUnicodeString(newBufferReader(), raw, 0, 1024)
	if err == nil || !strings.Contains(err.Error(), "odd") {
		t.Errorf("expected odd-length error, got %v", err)
	}
}

func TestReadLSAUnicodeString_RejectsLengthGTMaxLength(t *testing.T) {
	raw := make([]byte, 0x40)
	binary.LittleEndian.PutUint16(raw[0:2], 100) // Length
	binary.LittleEndian.PutUint16(raw[2:4], 50)  // MaxLength (less than Length)
	binary.LittleEndian.PutUint64(raw[8:16], 0xAA0000)
	_, err := readLSAUnicodeString(newBufferReader(), raw, 0, 1024)
	if err == nil || !strings.Contains(err.Error(), "exceeds MaximumLength") {
		t.Errorf("expected MaximumLength error, got %v", err)
	}
}

func TestReadLSAUnicodeString_RejectsSanityCapExceeded(t *testing.T) {
	raw := make([]byte, 0x40)
	stampUnicodeStringHeader(raw, 0, 5000, 0xAA0000)
	_, err := readLSAUnicodeString(newBufferReader(), raw, 0, 1024)
	if err == nil || !strings.Contains(err.Error(), "sanity cap") {
		t.Errorf("expected sanity-cap error, got %v", err)
	}
}

func TestReadLSAUnicodeString_RemoteReadFails(t *testing.T) {
	raw := make([]byte, 0x40)
	stampUnicodeStringHeader(raw, 0, 8, 0xAA0000) // page not registered
	_, err := readLSAUnicodeString(newBufferReader(), raw, 0, 1024)
	if err == nil || !strings.Contains(err.Error(), "read LSA_UNICODE_STRING") {
		t.Errorf("expected read failure, got %v", err)
	}
}

func TestReadLSAUnicodeString_FieldOffsetOutsideNode(t *testing.T) {
	raw := make([]byte, 16) // exactly one header
	_, err := readLSAUnicodeString(newBufferReader(), raw, 8, 1024)
	if err == nil || !strings.Contains(err.Error(), "outside captured node") {
		t.Errorf("expected outside-node error, got %v", err)
	}
}

func TestReadLSAUnicodeString_NilReader(t *testing.T) {
	raw := make([]byte, 0x40)
	stampUnicodeStringHeader(raw, 0, 8, 0xAA0000)
	_, err := readLSAUnicodeString(nil, raw, 0, 1024)
	if err == nil || !strings.Contains(err.Error(), "nil lsassReader") {
		t.Errorf("expected nil-reader error, got %v", err)
	}
}

func TestParseLogonSessionFields_FullNode(t *testing.T) {
	const (
		userBufAddr   = uintptr(0xAA0000)
		domainBufAddr = uintptr(0xBB0000)
		typeBufAddr   = uintptr(0xCC0000)
		serverBufAddr = uintptr(0xDD0000)
		credsListAddr = uintptr(0xC0FFEE00)
		luid          = uint64(0x000003E700000123)
	)
	r := newBufferReader()
	r.put(userBufAddr, utf16LEBytes("alice"))
	r.put(domainBufAddr, utf16LEBytes("CORP"))
	r.put(typeBufAddr, utf16LEBytes("NTLM"))
	r.put(serverBufAddr, utf16LEBytes("DC01"))

	node := makeFullNode(0xFEED1, 0xFEED2, luid, 2 /* Interactive */, credsListAddr)
	stampUnicodeStringHeader(node, LayoutWin10New.UserNameOffset, uint16(len("alice")*2), userBufAddr)
	stampUnicodeStringHeader(node, LayoutWin10New.DomainOffset, uint16(len("CORP")*2), domainBufAddr)
	stampUnicodeStringHeader(node, LayoutWin10New.TypeOffset, uint16(len("NTLM")*2), typeBufAddr)
	stampUnicodeStringHeader(node, LayoutWin10New.LogonServerOff, uint16(len("DC01")*2), serverBufAddr)

	got := parseLogonSessionFields(r, node, LayoutWin10New)
	if len(got.ParseErrors) != 0 {
		t.Errorf("unexpected ParseErrors: %v", got.ParseErrors)
	}
	if got.LUID != luid {
		t.Errorf("LUID = 0x%X, want 0x%X", got.LUID, luid)
	}
	if got.UserName != "alice" {
		t.Errorf("UserName = %q, want %q", got.UserName, "alice")
	}
	if got.Domain != "CORP" {
		t.Errorf("Domain = %q, want %q", got.Domain, "CORP")
	}
	if got.AuthPackage != "NTLM" {
		t.Errorf("AuthPackage = %q, want %q", got.AuthPackage, "NTLM")
	}
	if got.LogonServer != "DC01" {
		t.Errorf("LogonServer = %q, want %q", got.LogonServer, "DC01")
	}
	if got.LogonType != 2 {
		t.Errorf("LogonType = %d, want 2", got.LogonType)
	}
	if got.CredentialsPtr != credsListAddr {
		t.Errorf("CredentialsPtr = 0x%X, want 0x%X", got.CredentialsPtr, credsListAddr)
	}
}

func TestParseLogonSessionFields_PartialFailure(t *testing.T) {
	const (
		userBufAddr   = uintptr(0xAA0000)
		domainBufAddr = uintptr(0xBB0000) // intentionally NOT registered → remote read fails
		luid          = uint64(0x000003E700000456)
	)
	r := newBufferReader()
	r.put(userBufAddr, utf16LEBytes("bob"))

	node := makeFullNode(0, 0, luid, 3, 0xDEADBEEF)
	stampUnicodeStringHeader(node, LayoutWin10New.UserNameOffset, uint16(len("bob")*2), userBufAddr)
	stampUnicodeStringHeader(node, LayoutWin10New.DomainOffset, 8, domainBufAddr) // unregistered page
	// Type and LogonServer left zero (Length=0, Buffer=0) → empty strings, no error

	got := parseLogonSessionFields(r, node, LayoutWin10New)
	if got.LUID != luid {
		t.Errorf("LUID = 0x%X, want 0x%X (parse should not be derailed by Domain failure)", got.LUID, luid)
	}
	if got.UserName != "bob" {
		t.Errorf("UserName = %q, want bob", got.UserName)
	}
	if got.Domain != "" {
		t.Errorf("Domain = %q, want empty (failed remote read)", got.Domain)
	}
	if got.LogonType != 3 {
		t.Errorf("LogonType = %d, want 3", got.LogonType)
	}
	if len(got.ParseErrors) != 1 {
		t.Fatalf("expected exactly 1 ParseError (Domain), got %d: %v", len(got.ParseErrors), got.ParseErrors)
	}
	if !strings.Contains(got.ParseErrors[0], "Domain") {
		t.Errorf("ParseError[0] = %q, want it to mention Domain", got.ParseErrors[0])
	}
}

func TestParseLogonSessionFields_ShortNodeBuffer(t *testing.T) {
	// A node smaller than the layout requires should produce ParseErrors for
	// every field that lands past the end of the buffer, but should not
	// panic.
	r := newBufferReader()
	short := make([]byte, 0x80) // smaller than LUIDOffset+8 (0x70+8=0x78), so LUID parses but UserName at +0x90 doesn't
	got := parseLogonSessionFields(r, short, LayoutWin10New)
	if got.LUID == 0 {
		// LUID at +0x70 would be readable in 0x80-byte buffer, parsed value
		// is whatever zero-fill is there → still 0 here, but check no panic.
	}
	// At minimum, UserName/Domain/Type/LogonServer/Credentials must error.
	if len(got.ParseErrors) == 0 {
		t.Errorf("expected ParseErrors for fields outside short buffer, got none")
	}
}

func TestLogonSessionTypeName(t *testing.T) {
	cases := map[uint32]string{
		0:    "",
		2:    "Interactive",
		3:    "Network",
		10:   "RemoteInteractive",
		13:   "CachedUnlock",
		9999: "Unknown(9999)",
	}
	for in, want := range cases {
		if got := logonSessionTypeName(in); got != want {
			t.Errorf("logonSessionTypeName(%d) = %q, want %q", in, got, want)
		}
	}
}

func TestReadAnsiString_Normal(t *testing.T) {
	br := &bufferReader{pages: make(map[uintptr][]byte)}
	data := []byte("Primary")
	br.pages[0x5000] = data
	raw := make([]byte, 16)
	binary.LittleEndian.PutUint16(raw[0:2], 7)   // Length
	binary.LittleEndian.PutUint16(raw[2:4], 8)    // MaxLength
	binary.LittleEndian.PutUint64(raw[8:16], 0x5000)
	s, err := readAnsiString(br, raw, 0, 1024)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s != "Primary" {
		t.Errorf("got %q, want %q", s, "Primary")
	}
}

func TestReadAnsiString_OddLength(t *testing.T) {
	br := &bufferReader{pages: make(map[uintptr][]byte)}
	br.pages[0x6000] = []byte("WDigest")
	raw := make([]byte, 16)
	binary.LittleEndian.PutUint16(raw[0:2], 7)   // Odd length = valid for ANSI
	binary.LittleEndian.PutUint16(raw[2:4], 8)
	binary.LittleEndian.PutUint64(raw[8:16], 0x6000)
	s, err := readAnsiString(br, raw, 0, 1024)
	if err != nil {
		t.Fatalf("odd length should be accepted for ANSI: %v", err)
	}
	if s != "WDigest" {
		t.Errorf("got %q, want %q", s, "WDigest")
	}
}

func TestReadAnsiString_Empty(t *testing.T) {
	br := &bufferReader{pages: make(map[uintptr][]byte)}
	raw := make([]byte, 16) // All zeros → Length=0
	s, err := readAnsiString(br, raw, 0, 1024)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s != "" {
		t.Errorf("got %q, want empty", s)
	}
}
