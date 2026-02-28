package agentfunctions

import (
	"encoding/base64"
	"encoding/binary"
	"strings"
	"testing"
)

// --- xorEncodeString tests ---

func TestXorEncodeString_Basic(t *testing.T) {
	key := []byte{0x41, 0x42, 0x43, 0x44} // ABCD
	encoded := xorEncodeString("hello", key)
	if encoded == "" {
		t.Fatal("expected non-empty encoded string")
	}
	if encoded == "hello" {
		t.Error("encoded should differ from plaintext")
	}
	// Verify it's valid base64
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("expected valid base64, got error: %v", err)
	}
	if len(decoded) != 5 {
		t.Errorf("expected 5 decoded bytes, got %d", len(decoded))
	}
}

func TestXorEncodeString_Roundtrip(t *testing.T) {
	key := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	plaintext := "https://c2.example.com:443/api/v1"
	encoded := xorEncodeString(plaintext, key)

	// Decode base64
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("base64 decode error: %v", err)
	}
	// XOR again to recover plaintext
	result := make([]byte, len(decoded))
	for i, b := range decoded {
		result[i] = b ^ key[i%len(key)]
	}
	if string(result) != plaintext {
		t.Errorf("roundtrip failed: got %q, want %q", string(result), plaintext)
	}
}

func TestXorEncodeString_EmptyPlaintext(t *testing.T) {
	key := []byte{0x01, 0x02}
	result := xorEncodeString("", key)
	if result != "" {
		t.Errorf("expected empty string for empty plaintext, got %q", result)
	}
}

func TestXorEncodeString_EmptyKey(t *testing.T) {
	result := xorEncodeString("hello", []byte{})
	if result != "hello" {
		t.Errorf("expected plaintext returned for empty key, got %q", result)
	}
}

func TestXorEncodeString_SingleByteKey(t *testing.T) {
	key := []byte{0xFF}
	encoded := xorEncodeString("AB", key)
	decoded, _ := base64.StdEncoding.DecodeString(encoded)
	// 'A' (0x41) ^ 0xFF = 0xBE, 'B' (0x42) ^ 0xFF = 0xBD
	if decoded[0] != 0xBE || decoded[1] != 0xBD {
		t.Errorf("unexpected XOR result: %x %x", decoded[0], decoded[1])
	}
}

func TestXorEncodeString_LongKey(t *testing.T) {
	// Key longer than plaintext — should still work (wraps via modulo)
	key := make([]byte, 64)
	for i := range key {
		key[i] = byte(i)
	}
	encoded := xorEncodeString("hi", key)
	decoded, _ := base64.StdEncoding.DecodeString(encoded)
	if decoded[0] != 'h'^0 || decoded[1] != 'i'^1 {
		t.Errorf("unexpected XOR with long key: %x %x", decoded[0], decoded[1])
	}
}

// --- extractLdflagValue tests ---

func TestExtractLdflagValue_Basic(t *testing.T) {
	ldflags := "-s -w -X 'main.payloadUUID=abc-123' -X 'main.callbackHost=https://example.com'"
	val := extractLdflagValue(ldflags, "main", "payloadUUID")
	if val != "abc-123" {
		t.Errorf("expected 'abc-123', got %q", val)
	}
}

func TestExtractLdflagValue_URL(t *testing.T) {
	ldflags := "-X 'main.callbackHost=https://c2.evil.com:8443' -X 'main.callbackPort=443'"
	val := extractLdflagValue(ldflags, "main", "callbackHost")
	if val != "https://c2.evil.com:8443" {
		t.Errorf("expected URL, got %q", val)
	}
}

func TestExtractLdflagValue_NotFound(t *testing.T) {
	ldflags := "-X 'main.callbackHost=test'"
	val := extractLdflagValue(ldflags, "main", "nonexistent")
	if val != "" {
		t.Errorf("expected empty string for missing var, got %q", val)
	}
}

func TestExtractLdflagValue_EmptyValue(t *testing.T) {
	ldflags := "-X 'main.empty=' -X 'main.other=val'"
	val := extractLdflagValue(ldflags, "main", "empty")
	if val != "" {
		t.Errorf("expected empty string, got %q", val)
	}
}

func TestExtractLdflagValue_MultipleVars(t *testing.T) {
	ldflags := "-s -w -X 'main.payloadUUID=uuid1' -X 'main.callbackHost=host1' -X 'main.encryptionKey=key1'"
	tests := []struct {
		varName string
		want    string
	}{
		{"payloadUUID", "uuid1"},
		{"callbackHost", "host1"},
		{"encryptionKey", "key1"},
	}
	for _, tc := range tests {
		got := extractLdflagValue(ldflags, "main", tc.varName)
		if got != tc.want {
			t.Errorf("extractLdflagValue(%q) = %q, want %q", tc.varName, got, tc.want)
		}
	}
}

func TestExtractLdflagValue_Base64Value(t *testing.T) {
	// XOR-encoded values are base64 — contains +, /, = chars
	b64val := base64.StdEncoding.EncodeToString([]byte("test-encoded-value"))
	ldflags := "-X 'main.callbackHost=" + b64val + "'"
	val := extractLdflagValue(ldflags, "main", "callbackHost")
	if val != b64val {
		t.Errorf("expected base64 value %q, got %q", b64val, val)
	}
}

func TestExtractLdflagValue_DifferentPkg(t *testing.T) {
	ldflags := "-X 'main.foo=bar' -X 'pkg.foo=baz'"
	val := extractLdflagValue(ldflags, "pkg", "foo")
	if val != "baz" {
		t.Errorf("expected 'baz' for pkg.foo, got %q", val)
	}
}

// --- is64BitDLL tests ---

func TestIs64BitDLL_TooShort(t *testing.T) {
	if is64BitDLL([]byte{0, 1, 2}) {
		t.Error("expected false for short input")
	}
}

func TestIs64BitDLL_InvalidPEOffset(t *testing.T) {
	// 64 bytes but PE offset points beyond the data
	data := make([]byte, 64)
	binary.LittleEndian.PutUint32(data[60:64], 0xFFFF) // PE offset way out of bounds
	if is64BitDLL(data) {
		t.Error("expected false for invalid PE offset")
	}
}

func TestIs64BitDLL_AMD64(t *testing.T) {
	// Build a minimal valid PE-like structure
	data := make([]byte, 100)
	peOffset := uint32(80)
	binary.LittleEndian.PutUint32(data[60:64], peOffset)
	// PE signature at peOffset: "PE\0\0"
	data[peOffset] = 'P'
	data[peOffset+1] = 'E'
	// Machine type at peOffset+4
	binary.LittleEndian.PutUint16(data[peOffset+4:peOffset+6], 0x8664) // AMD64
	if !is64BitDLL(data) {
		t.Error("expected true for AMD64 machine type")
	}
}

func TestIs64BitDLL_IA64(t *testing.T) {
	data := make([]byte, 100)
	peOffset := uint32(80)
	binary.LittleEndian.PutUint32(data[60:64], peOffset)
	binary.LittleEndian.PutUint16(data[peOffset+4:peOffset+6], 0x0200) // IA64
	if !is64BitDLL(data) {
		t.Error("expected true for IA64 machine type")
	}
}

func TestIs64BitDLL_I386(t *testing.T) {
	data := make([]byte, 100)
	peOffset := uint32(80)
	binary.LittleEndian.PutUint32(data[60:64], peOffset)
	binary.LittleEndian.PutUint16(data[peOffset+4:peOffset+6], 0x014C) // i386
	if is64BitDLL(data) {
		t.Error("expected false for i386 machine type")
	}
}

func TestIs64BitDLL_ARM(t *testing.T) {
	data := make([]byte, 100)
	peOffset := uint32(80)
	binary.LittleEndian.PutUint32(data[60:64], peOffset)
	binary.LittleEndian.PutUint16(data[peOffset+4:peOffset+6], 0x01C0) // ARM
	if is64BitDLL(data) {
		t.Error("expected false for ARM machine type")
	}
}

func TestIs64BitDLL_ExactBoundary(t *testing.T) {
	// PE offset at boundary — data is exactly large enough
	data := make([]byte, 70)
	peOffset := uint32(64)
	binary.LittleEndian.PutUint32(data[60:64], peOffset)
	binary.LittleEndian.PutUint16(data[peOffset+4:peOffset+6], 0x8664) // AMD64
	if !is64BitDLL(data) {
		t.Error("expected true for AMD64 at exact boundary")
	}
}

// --- xorEncodeString + extractLdflagValue integration ---

func TestXorEncode_ExtractLdflag_Integration(t *testing.T) {
	// Simulate the builder's obfuscation pipeline:
	// 1. Build ldflags with plaintext
	// 2. XOR-encode the value
	// 3. Replace in ldflags
	// 4. Extract the encoded value
	// 5. Verify it decodes back to original
	key := []byte{0xAA, 0xBB, 0xCC, 0xDD}
	plaintext := "https://c2.example.com"

	ldflags := "-s -w -X 'main.callbackHost=" + plaintext + "'"

	// Encode
	encoded := xorEncodeString(plaintext, key)
	plainPattern := "-X 'main.callbackHost=" + plaintext + "'"
	encodedPattern := "-X 'main.callbackHost=" + encoded + "'"
	ldflags = strings.Replace(ldflags, plainPattern, encodedPattern, 1)

	// Extract
	extracted := extractLdflagValue(ldflags, "main", "callbackHost")
	if extracted != encoded {
		t.Errorf("extraction failed: got %q, want %q", extracted, encoded)
	}

	// Decode and verify
	decoded, _ := base64.StdEncoding.DecodeString(extracted)
	result := make([]byte, len(decoded))
	for i, b := range decoded {
		result[i] = b ^ key[i%len(key)]
	}
	if string(result) != plaintext {
		t.Errorf("full pipeline roundtrip failed: got %q, want %q", string(result), plaintext)
	}
}
