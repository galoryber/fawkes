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

// --- formatEntropyAssessment tests ---

func TestFormatEntropyAssessment_VeryHigh(t *testing.T) {
	entOutput := `Entropy = 7.9523 bits per byte.

Optimum compression would reduce the size
of this 8388608 byte file by 0 percent.

Chi square distribution for 8388608 samples is 260.52, and randomly
would exceed this value 42.50 percent of the times.

Arithmetic mean value of data bytes is 127.4982 (127.5 = random).
Monte Carlo value for Pi is 3.141803253 (0.01 percent error).
Serial correlation coefficient is -0.000189 (totally uncorrelated = 0.0).`

	result := formatEntropyAssessment(entOutput)
	if !strings.Contains(result, "VERY HIGH") {
		t.Errorf("expected VERY HIGH for entropy 7.9523, got: %s", result)
	}
	if !strings.Contains(result, "inflate_bytes") {
		t.Error("expected inflate_bytes recommendation for very high entropy")
	}
}

func TestFormatEntropyAssessment_High(t *testing.T) {
	entOutput := "Entropy = 7.6234 bits per byte.\n\nSome other stats..."
	result := formatEntropyAssessment(entOutput)
	if !strings.Contains(result, "HIGH") {
		t.Errorf("expected HIGH for entropy 7.6234, got: %s", result)
	}
	if !strings.Contains(result, "Go binaries") {
		t.Error("expected Go binary note for high entropy")
	}
}

func TestFormatEntropyAssessment_Moderate(t *testing.T) {
	entOutput := "Entropy = 6.5000 bits per byte.\n"
	result := formatEntropyAssessment(entOutput)
	if !strings.Contains(result, "MODERATE") {
		t.Errorf("expected MODERATE for entropy 6.5, got: %s", result)
	}
}

func TestFormatEntropyAssessment_Low(t *testing.T) {
	entOutput := "Entropy = 4.2100 bits per byte.\n"
	result := formatEntropyAssessment(entOutput)
	if !strings.Contains(result, "LOW") {
		t.Errorf("expected LOW for entropy 4.21, got: %s", result)
	}
}

func TestFormatEntropyAssessment_NoEntropy(t *testing.T) {
	entOutput := "Some random output without entropy line"
	result := formatEntropyAssessment(entOutput)
	if result != "" {
		t.Errorf("expected empty result for missing entropy, got: %q", result)
	}
}

func TestFormatEntropyAssessment_Boundary79(t *testing.T) {
	// Exactly 7.9 — should be HIGH not VERY HIGH
	entOutput := "Entropy = 7.8999 bits per byte.\n"
	result := formatEntropyAssessment(entOutput)
	if !strings.Contains(result, "HIGH") || strings.Contains(result, "VERY HIGH") {
		t.Errorf("expected HIGH (not VERY HIGH) for entropy 7.8999, got: %s", result)
	}
}

func TestFormatEntropyAssessment_Boundary75(t *testing.T) {
	// Exactly 7.5 — should be HIGH
	entOutput := "Entropy = 7.5000 bits per byte.\n"
	result := formatEntropyAssessment(entOutput)
	if !strings.Contains(result, "HIGH") {
		t.Errorf("expected HIGH for entropy 7.5, got: %s", result)
	}
}

func TestFormatEntropyAssessment_Boundary60(t *testing.T) {
	// Exactly 6.0 — should be MODERATE
	entOutput := "Entropy = 6.0000 bits per byte.\n"
	result := formatEntropyAssessment(entOutput)
	if !strings.Contains(result, "MODERATE") {
		t.Errorf("expected MODERATE for entropy 6.0, got: %s", result)
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

// --- parseInflateHexBytes tests ---

func TestParseInflateHexBytes_SingleByte(t *testing.T) {
	result, err := parseInflateHexBytes("0x90")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result) != 1 || result[0] != 0x90 {
		t.Errorf("got %x, want [90]", result)
	}
}

func TestParseInflateHexBytes_MultiByte(t *testing.T) {
	result, err := parseInflateHexBytes("0x41,0x42")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result) != 2 || result[0] != 0x41 || result[1] != 0x42 {
		t.Errorf("got %x, want [41 42]", result)
	}
}

func TestParseInflateHexBytes_NoPrefix(t *testing.T) {
	result, err := parseInflateHexBytes("90")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result) != 1 || result[0] != 0x90 {
		t.Errorf("got %x, want [90]", result)
	}
}

func TestParseInflateHexBytes_MixedCase(t *testing.T) {
	result, err := parseInflateHexBytes("0XFF,0xff,FF")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result) != 3 {
		t.Fatalf("got %d bytes, want 3", len(result))
	}
	for i, b := range result {
		if b != 0xFF {
			t.Errorf("byte %d: got %x, want ff", i, b)
		}
	}
}

func TestParseInflateHexBytes_WithSpaces(t *testing.T) {
	result, err := parseInflateHexBytes("0x00, 0x90")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result) != 2 || result[0] != 0x00 || result[1] != 0x90 {
		t.Errorf("got %x, want [00 90]", result)
	}
}

func TestParseInflateHexBytes_Invalid(t *testing.T) {
	_, err := parseInflateHexBytes("0xZZ")
	if err == nil {
		t.Error("expected error for invalid hex")
	}
}

func TestParseInflateHexBytes_TooLarge(t *testing.T) {
	_, err := parseInflateHexBytes("0x1FF")
	if err == nil {
		t.Error("expected error for >8-bit value")
	}
}

// --- generatePaddingData tests ---

func TestGeneratePaddingData_SingleByte(t *testing.T) {
	data := generatePaddingData([]byte{0x90}, 5)
	if len(data) != 5 {
		t.Fatalf("got %d bytes, want 5", len(data))
	}
	for i, b := range data {
		if b != 0x90 {
			t.Errorf("byte %d: got %x, want 90", i, b)
		}
	}
}

func TestGeneratePaddingData_Pattern(t *testing.T) {
	data := generatePaddingData([]byte{0x41, 0x42}, 3)
	expected := []byte{0x41, 0x42, 0x41, 0x42, 0x41, 0x42}
	if len(data) != len(expected) {
		t.Fatalf("got %d bytes, want %d", len(data), len(expected))
	}
	for i := range data {
		if data[i] != expected[i] {
			t.Errorf("byte %d: got %x, want %x", i, data[i], expected[i])
		}
	}
}

func TestGeneratePaddingData_LargeCount(t *testing.T) {
	data := generatePaddingData([]byte{0x00, 0x90}, 1000000)
	if len(data) != 2000000 {
		t.Errorf("got %d bytes, want 2000000", len(data))
	}
}

func TestGeneratePaddingData_ZeroCount(t *testing.T) {
	data := generatePaddingData([]byte{0x90}, 0)
	if len(data) != 0 {
		t.Errorf("got %d bytes, want 0", len(data))
	}
}

// --- payloadFileExtension tests ---

func TestPayloadFileExtension_SharedWindows(t *testing.T) {
	if ext := payloadFileExtension("shared", "windows"); ext != "dll" {
		t.Errorf("shared+windows: got %q, want dll", ext)
	}
}

func TestPayloadFileExtension_SharedDarwin(t *testing.T) {
	if ext := payloadFileExtension("shared", "darwin"); ext != "dylib" {
		t.Errorf("shared+darwin: got %q, want dylib", ext)
	}
}

func TestPayloadFileExtension_SharedLinux(t *testing.T) {
	if ext := payloadFileExtension("shared", "linux"); ext != "so" {
		t.Errorf("shared+linux: got %q, want so", ext)
	}
}

func TestPayloadFileExtension_DefaultWindows(t *testing.T) {
	if ext := payloadFileExtension("default-executable", "windows"); ext != "exe" {
		t.Errorf("default+windows: got %q, want exe", ext)
	}
}

func TestPayloadFileExtension_DefaultLinux(t *testing.T) {
	if ext := payloadFileExtension("default-executable", "linux"); ext != "bin" {
		t.Errorf("default+linux: got %q, want bin", ext)
	}
}

func TestPayloadFileExtension_DefaultDarwin(t *testing.T) {
	if ext := payloadFileExtension("default-executable", "darwin"); ext != "bin" {
		t.Errorf("default+darwin: got %q, want bin", ext)
	}
}

// --- constructBuildCommand tests ---

func TestConstructBuildCommand_DefaultLinux(t *testing.T) {
	result := constructBuildCommand(buildCommandConfig{
		targetOs:      "linux",
		goarch:        "amd64",
		mode:          "default-executable",
		garble:        false,
		c2ProfileName: "http",
		payloadUUID:   "test-uuid",
		macOSVersion:  "10.12",
		ldflags:       "-s -w",
	})
	if !strings.Contains(result.command, "GOOS=linux") {
		t.Error("expected GOOS=linux in command")
	}
	if !strings.Contains(result.command, "GOARCH=amd64") {
		t.Error("expected GOARCH=amd64 in command")
	}
	if !strings.Contains(result.command, "go build") {
		t.Error("expected 'go build' (not garble) in command")
	}
	if !strings.Contains(result.command, "-tags http") {
		t.Error("expected -tags http in command")
	}
	if result.payloadName != "test-uuid-linux-amd64" {
		t.Errorf("payloadName: got %q, want test-uuid-linux-amd64", result.payloadName)
	}
}

func TestConstructBuildCommand_DefaultWindows(t *testing.T) {
	result := constructBuildCommand(buildCommandConfig{
		targetOs:      "windows",
		goarch:        "amd64",
		mode:          "default-executable",
		garble:        false,
		c2ProfileName: "http",
		payloadUUID:   "test-uuid",
		ldflags:       "-s -w",
	})
	// Windows default mode should enable CGO for go-coff BOF
	if !strings.Contains(result.command, "CGO_ENABLED=1") {
		t.Error("expected CGO_ENABLED=1 for Windows default mode")
	}
	if !strings.Contains(result.command, "CC=x86_64-w64-mingw32-gcc") {
		t.Error("expected mingw cross-compiler for Windows amd64")
	}
}

func TestConstructBuildCommand_SharedWindows(t *testing.T) {
	result := constructBuildCommand(buildCommandConfig{
		targetOs:      "windows",
		goarch:        "amd64",
		mode:          "shared",
		garble:        false,
		c2ProfileName: "http",
		payloadUUID:   "test-uuid",
		ldflags:       "-s -w",
	})
	if !strings.Contains(result.command, "c-shared") {
		t.Error("expected -buildmode c-shared for shared mode")
	}
	if !strings.Contains(result.command, "-tags http,shared") {
		t.Error("expected shared tag appended")
	}
	if !strings.HasSuffix(result.payloadName, ".dll") {
		t.Errorf("shared+windows payloadName should end in .dll, got %q", result.payloadName)
	}
}

func TestConstructBuildCommand_SharedDarwin(t *testing.T) {
	result := constructBuildCommand(buildCommandConfig{
		targetOs:      "darwin",
		goarch:        "arm64",
		mode:          "shared",
		garble:        false,
		c2ProfileName: "http",
		payloadUUID:   "test-uuid",
		macOSVersion:  "10.12",
		ldflags:       "-s -w",
	})
	if !strings.Contains(result.command, "CC=o64-clang") {
		t.Error("expected o64-clang cross-compiler for Darwin shared")
	}
	if !strings.HasSuffix(result.payloadName, ".dylib") {
		t.Errorf("shared+darwin payloadName should end in .dylib, got %q", result.payloadName)
	}
	if !strings.Contains(result.payloadName, "10.12") {
		t.Error("expected macOSVersion in Darwin payload name")
	}
}

func TestConstructBuildCommand_Shellcode(t *testing.T) {
	result := constructBuildCommand(buildCommandConfig{
		targetOs:      "windows",
		goarch:        "amd64",
		mode:          "windows-shellcode",
		garble:        false,
		c2ProfileName: "http",
		payloadUUID:   "test-uuid",
		ldflags:       "-s -w",
	})
	// Shellcode builds as DLL first
	if !strings.Contains(result.command, "c-shared") {
		t.Error("expected -buildmode c-shared for shellcode mode")
	}
	if !strings.HasSuffix(result.payloadName, ".dll") {
		t.Errorf("shellcode payloadName should end in .dll, got %q", result.payloadName)
	}
}

func TestConstructBuildCommand_Garble(t *testing.T) {
	result := constructBuildCommand(buildCommandConfig{
		targetOs:      "linux",
		goarch:        "amd64",
		mode:          "default-executable",
		garble:        true,
		c2ProfileName: "http",
		payloadUUID:   "test-uuid",
		ldflags:       "-s -w",
	})
	if !strings.Contains(result.command, "/go/bin/garble") {
		t.Error("expected garble command when garble=true")
	}
	if !strings.Contains(result.command, "-tiny -literals -seed random") {
		t.Error("expected garble flags")
	}
	if strings.Contains(result.command, "go build") && !strings.Contains(result.command, "garble") {
		t.Error("should use garble, not plain go build")
	}
}

func TestConstructBuildCommand_LinuxARM64Shared(t *testing.T) {
	result := constructBuildCommand(buildCommandConfig{
		targetOs:      "linux",
		goarch:        "arm64",
		mode:          "shared",
		garble:        false,
		c2ProfileName: "tcp",
		payloadUUID:   "test-uuid",
		ldflags:       "-s -w",
	})
	if !strings.Contains(result.command, "CC=aarch64-linux-gnu-gcc") {
		t.Error("expected aarch64 cross-compiler for Linux arm64 shared")
	}
	if !strings.HasSuffix(result.payloadName, ".so") {
		t.Errorf("shared+linux payloadName should end in .so, got %q", result.payloadName)
	}
}

func TestConstructBuildCommand_GOGARBLEScope(t *testing.T) {
	result := constructBuildCommand(buildCommandConfig{
		targetOs:      "linux",
		goarch:        "amd64",
		mode:          "default-executable",
		garble:        false,
		c2ProfileName: "http",
		payloadUUID:   "test-uuid",
		ldflags:       "-s -w",
	})
	if !strings.Contains(result.command, "GOGARBLE=fawkes") {
		t.Error("expected GOGARBLE=fawkes scope restriction")
	}
}

func TestConstructBuildCommand_CacheClearing(t *testing.T) {
	result := constructBuildCommand(buildCommandConfig{
		targetOs:      "linux",
		goarch:        "amd64",
		mode:          "default-executable",
		garble:        false,
		c2ProfileName: "http",
		payloadUUID:   "test-uuid",
		ldflags:       "-s -w",
	})
	if !strings.Contains(result.command, "go clean -cache") {
		t.Error("expected go clean -cache for cache clearing")
	}
	if !strings.Contains(result.command, "rm -rf") {
		t.Error("expected garble cache cleanup")
	}
}
