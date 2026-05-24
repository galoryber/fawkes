package commands

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestBase64Name(t *testing.T) {
	c := &Base64Command{}
	if c.Name() != "base64" {
		t.Errorf("expected 'base64', got '%s'", c.Name())
	}
}

func TestBase64Description(t *testing.T) {
	c := &Base64Command{}
	if c.Description() == "" {
		t.Error("description should not be empty")
	}
}

func TestBase64EmptyParams(t *testing.T) {
	c := &Base64Command{}
	result := c.Execute(structs.Task{Params: ""})
	if result.Status != "error" {
		t.Errorf("expected error, got %s", result.Status)
	}
}

func TestBase64BadJSON(t *testing.T) {
	c := &Base64Command{}
	result := c.Execute(structs.Task{Params: "not json"})
	if result.Status != "error" {
		t.Errorf("expected error, got %s", result.Status)
	}
}

func TestBase64MissingInput(t *testing.T) {
	c := &Base64Command{}
	params, _ := json.Marshal(base64Args{Action: "encode"})
	result := c.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error, got %s", result.Status)
	}
}

func TestBase64InvalidAction(t *testing.T) {
	c := &Base64Command{}
	params, _ := json.Marshal(base64Args{Action: "invalid", Input: "test"})
	result := c.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error, got %s", result.Status)
	}
}

func TestBase64EncodeString(t *testing.T) {
	c := &Base64Command{}
	params, _ := json.Marshal(base64Args{Action: "encode", Input: "hello world"})
	result := c.Execute(structs.Task{Params: string(params)})

	if result.Status != "success" {
		t.Fatalf("expected success, got %s: %s", result.Status, result.Output)
	}
	expected := base64.StdEncoding.EncodeToString([]byte("hello world"))
	if !strings.Contains(result.Output, expected) {
		t.Errorf("expected output to contain '%s', got: %s", expected, result.Output)
	}
}

func TestBase64DecodeString(t *testing.T) {
	c := &Base64Command{}
	encoded := base64.StdEncoding.EncodeToString([]byte("hello world"))
	params, _ := json.Marshal(base64Args{Action: "decode", Input: encoded})
	result := c.Execute(structs.Task{Params: string(params)})

	if result.Status != "success" {
		t.Fatalf("expected success, got %s: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "hello world") {
		t.Errorf("expected 'hello world' in output, got: %s", result.Output)
	}
}

func TestBase64DefaultActionEncode(t *testing.T) {
	c := &Base64Command{}
	// No action specified — should default to encode
	params, _ := json.Marshal(base64Args{Input: "test"})
	result := c.Execute(structs.Task{Params: string(params)})

	if result.Status != "success" {
		t.Fatalf("expected success, got %s: %s", result.Status, result.Output)
	}
	expected := base64.StdEncoding.EncodeToString([]byte("test"))
	if !strings.Contains(result.Output, expected) {
		t.Error("default action should encode")
	}
}

func TestBase64EncodeFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "input.txt")
	os.WriteFile(path, []byte("file content"), 0644)

	c := &Base64Command{}
	params, _ := json.Marshal(base64Args{Action: "encode", Input: path, File: true})
	result := c.Execute(structs.Task{Params: string(params)})

	if result.Status != "success" {
		t.Fatalf("expected success, got %s: %s", result.Status, result.Output)
	}
	expected := base64.StdEncoding.EncodeToString([]byte("file content"))
	if !strings.Contains(result.Output, expected) {
		t.Error("should contain base64-encoded file content")
	}
}

func TestBase64DecodeToFile(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "output.bin")
	encoded := base64.StdEncoding.EncodeToString([]byte("decoded content"))

	c := &Base64Command{}
	params, _ := json.Marshal(base64Args{Action: "decode", Input: encoded, Output: outPath})
	result := c.Execute(structs.Task{Params: string(params)})

	if result.Status != "success" {
		t.Fatalf("expected success, got %s: %s", result.Status, result.Output)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "decoded content" {
		t.Errorf("expected 'decoded content', got '%s'", string(data))
	}
}

func TestBase64EncodeToFile(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "encoded.txt")

	c := &Base64Command{}
	params, _ := json.Marshal(base64Args{Action: "encode", Input: "test data", Output: outPath})
	result := c.Execute(structs.Task{Params: string(params)})

	if result.Status != "success" {
		t.Fatalf("expected success, got %s: %s", result.Status, result.Output)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	expected := base64.StdEncoding.EncodeToString([]byte("test data"))
	if string(data) != expected {
		t.Errorf("expected '%s', got '%s'", expected, string(data))
	}
}

func TestBase64DecodeFromFile(t *testing.T) {
	dir := t.TempDir()
	// Write base64-encoded content to a file
	encoded := base64.StdEncoding.EncodeToString([]byte("hello from file"))
	inPath := filepath.Join(dir, "encoded.txt")
	os.WriteFile(inPath, []byte(encoded), 0644)

	c := &Base64Command{}
	params, _ := json.Marshal(base64Args{Action: "decode", Input: inPath, File: true})
	result := c.Execute(structs.Task{Params: string(params)})

	if result.Status != "success" {
		t.Fatalf("expected success, got %s: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "hello from file") {
		t.Errorf("expected decoded text in output, got: %s", result.Output)
	}
}

func TestBase64DecodeFromFileToFile(t *testing.T) {
	dir := t.TempDir()
	encoded := base64.StdEncoding.EncodeToString([]byte("file to file"))
	inPath := filepath.Join(dir, "encoded.txt")
	outPath := filepath.Join(dir, "decoded.txt")
	os.WriteFile(inPath, []byte(encoded), 0644)

	c := &Base64Command{}
	params, _ := json.Marshal(base64Args{Action: "decode", Input: inPath, File: true, Output: outPath})
	result := c.Execute(structs.Task{Params: string(params)})

	if result.Status != "success" {
		t.Fatalf("expected success, got %s: %s", result.Status, result.Output)
	}
	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "file to file" {
		t.Errorf("expected 'file to file', got '%s'", string(data))
	}
}

func TestBase64DecodeNonexistentFile(t *testing.T) {
	c := &Base64Command{}
	params, _ := json.Marshal(base64Args{Action: "decode", Input: "/nonexistent/encoded.txt", File: true})
	result := c.Execute(structs.Task{Params: string(params)})

	if result.Status != "error" {
		t.Errorf("expected error for nonexistent decode file, got %s", result.Status)
	}
}

func TestBase64InvalidBase64(t *testing.T) {
	c := &Base64Command{}
	params, _ := json.Marshal(base64Args{Action: "decode", Input: "not!valid!base64!!!"})
	result := c.Execute(structs.Task{Params: string(params)})

	if result.Status != "error" {
		t.Errorf("expected error for invalid base64, got %s", result.Status)
	}
}

func TestBase64NonexistentFile(t *testing.T) {
	c := &Base64Command{}
	params, _ := json.Marshal(base64Args{Action: "encode", Input: "/nonexistent/file", File: true})
	result := c.Execute(structs.Task{Params: string(params)})

	if result.Status != "error" {
		t.Errorf("expected error, got %s", result.Status)
	}
}

func TestBase64EncodeToUnwritablePath(t *testing.T) {
	c := &Base64Command{}
	params, _ := json.Marshal(base64Args{Action: "encode", Input: "test", Output: "/nonexistent/dir/output.txt"})
	result := c.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error for unwritable output path, got %s", result.Status)
	}
	if !strings.Contains(result.Output, "Error writing output file") {
		t.Errorf("expected write error message, got: %s", result.Output)
	}
}

func TestBase64DecodeToUnwritablePath(t *testing.T) {
	c := &Base64Command{}
	encoded := base64.StdEncoding.EncodeToString([]byte("test"))
	params, _ := json.Marshal(base64Args{Action: "decode", Input: encoded, Output: "/nonexistent/dir/output.bin"})
	result := c.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error for unwritable output path, got %s", result.Status)
	}
	if !strings.Contains(result.Output, "Error writing output file") {
		t.Errorf("expected write error message, got: %s", result.Output)
	}
}

func TestBase64EncodeFileToFile(t *testing.T) {
	dir := t.TempDir()
	inPath := filepath.Join(dir, "input.txt")
	outPath := filepath.Join(dir, "output.txt")
	os.WriteFile(inPath, []byte("file encode to file test"), 0644)

	c := &Base64Command{}
	params, _ := json.Marshal(base64Args{Action: "encode", Input: inPath, File: true, Output: outPath})
	result := c.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Fatalf("expected success, got %s: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "written to") {
		t.Errorf("expected 'written to' in output, got: %s", result.Output)
	}
	data, _ := os.ReadFile(outPath)
	expected := base64.StdEncoding.EncodeToString([]byte("file encode to file test"))
	if string(data) != expected {
		t.Errorf("output file content mismatch")
	}
}

func TestBase64BinaryContent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "binary.bin")
	binData := []byte{0x00, 0x01, 0xFF, 0xFE, 0x80, 0x7F}
	os.WriteFile(path, binData, 0644)

	// Encode
	c := &Base64Command{}
	params, _ := json.Marshal(base64Args{Action: "encode", Input: path, File: true})
	result := c.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Fatalf("encode failed: %s", result.Output)
	}

	expected := base64.StdEncoding.EncodeToString(binData)
	if !strings.Contains(result.Output, expected) {
		t.Error("should contain correct base64 for binary data")
	}

	// Decode back
	outPath := filepath.Join(dir, "restored.bin")
	params, _ = json.Marshal(base64Args{Action: "decode", Input: expected, Output: outPath})
	result = c.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Fatalf("decode failed: %s", result.Output)
	}

	restored, _ := os.ReadFile(outPath)
	if len(restored) != len(binData) {
		t.Fatalf("expected %d bytes, got %d", len(binData), len(restored))
	}
	for i, b := range restored {
		if b != binData[i] {
			t.Errorf("byte %d: expected 0x%02x, got 0x%02x", i, binData[i], b)
		}
	}
}

// --- XOR Tests ---

func TestXORStringKey(t *testing.T) {
	c := &Base64Command{}
	params, _ := json.Marshal(base64Args{Action: "xor", Input: "hello", Key: "key"})
	result := c.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Fatalf("XOR failed: %s", result.Output)
	}
	// XOR is symmetric — XOR again to get original
	// "hello" XOR "key" should produce specific hex
	expected := make([]byte, 5)
	key := []byte("key")
	for i, b := range []byte("hello") {
		expected[i] = b ^ key[i%len(key)]
	}
	expectedHex := hex.EncodeToString(expected)
	if !strings.Contains(result.Output, expectedHex) {
		t.Errorf("expected hex output containing %s, got: %s", expectedHex, result.Output)
	}
}

func TestXORHexKey(t *testing.T) {
	c := &Base64Command{}
	params, _ := json.Marshal(base64Args{Action: "xor", Input: "AB", Key: "0xFF"})
	result := c.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Fatalf("XOR hex key failed: %s", result.Output)
	}
	// 'A' (0x41) XOR 0xFF = 0xBE, 'B' (0x42) XOR 0xFF = 0xBD
	if !strings.Contains(result.Output, "bebd") {
		t.Errorf("expected 'bebd' in output, got: %s", result.Output)
	}
}

func TestXORSymmetric(t *testing.T) {
	c := &Base64Command{}
	dir := t.TempDir()
	outPath := filepath.Join(dir, "xored.bin")

	// XOR "test data" with key
	params, _ := json.Marshal(base64Args{Action: "xor", Input: "test data", Key: "secret", Output: outPath})
	result := c.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Fatalf("XOR encode failed: %s", result.Output)
	}

	// XOR the output file again with same key — should get original back
	outPath2 := filepath.Join(dir, "decoded.bin")
	params, _ = json.Marshal(base64Args{Action: "xor", Input: outPath, Key: "secret", File: true, Output: outPath2})
	result = c.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Fatalf("XOR decode failed: %s", result.Output)
	}

	data, _ := os.ReadFile(outPath2)
	if string(data) != "test data" {
		t.Errorf("XOR not symmetric: expected 'test data', got '%s'", string(data))
	}
}

func TestXORMissingKey(t *testing.T) {
	c := &Base64Command{}
	params, _ := json.Marshal(base64Args{Action: "xor", Input: "hello"})
	result := c.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error for missing key, got %s", result.Status)
	}
}

func TestXORInvalidHexKey(t *testing.T) {
	c := &Base64Command{}
	params, _ := json.Marshal(base64Args{Action: "xor", Input: "hello", Key: "0xZZZZ"})
	result := c.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error for invalid hex key, got %s", result.Status)
	}
}

// --- Hex Tests ---

func TestHexEncode(t *testing.T) {
	c := &Base64Command{}
	params, _ := json.Marshal(base64Args{Action: "hex", Input: "Hello"})
	result := c.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Fatalf("hex encode failed: %s", result.Output)
	}
	if !strings.Contains(result.Output, "48656c6c6f") {
		t.Errorf("expected hex '48656c6c6f', got: %s", result.Output)
	}
}

func TestHexDecode(t *testing.T) {
	c := &Base64Command{}
	params, _ := json.Marshal(base64Args{Action: "hex-decode", Input: "48656c6c6f"})
	result := c.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Fatalf("hex decode failed: %s", result.Output)
	}
	if !strings.Contains(result.Output, "Hello") {
		t.Errorf("expected 'Hello', got: %s", result.Output)
	}
}

func TestHexDecodeWithSpaces(t *testing.T) {
	c := &Base64Command{}
	params, _ := json.Marshal(base64Args{Action: "hex-decode", Input: "48 65 6c 6c 6f"})
	result := c.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Fatalf("hex decode with spaces failed: %s", result.Output)
	}
	if !strings.Contains(result.Output, "Hello") {
		t.Errorf("expected 'Hello', got: %s", result.Output)
	}
}

func TestHexDecodeInvalid(t *testing.T) {
	c := &Base64Command{}
	params, _ := json.Marshal(base64Args{Action: "hex-decode", Input: "ZZZZ"})
	result := c.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error for invalid hex, got %s", result.Status)
	}
}

func TestHexRoundTrip(t *testing.T) {
	c := &Base64Command{}
	dir := t.TempDir()
	// Use file-based input for binary data (avoids JSON UTF-8 encoding issues)
	inPath := filepath.Join(dir, "input.bin")
	outHex := filepath.Join(dir, "hex.txt")
	outBin := filepath.Join(dir, "decoded.bin")
	binData := []byte{0x00, 0x01, 0x7F, 0x80, 0xFE, 0xFF}
	os.WriteFile(inPath, binData, 0644)

	// Hex encode from file
	params, _ := json.Marshal(base64Args{Action: "hex", Input: inPath, File: true, Output: outHex})
	result := c.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Fatalf("hex encode failed: %s", result.Output)
	}

	// Hex decode from file
	params, _ = json.Marshal(base64Args{Action: "hex-decode", Input: outHex, File: true, Output: outBin})
	result = c.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Fatalf("hex decode failed: %s", result.Output)
	}

	data, _ := os.ReadFile(outBin)
	if len(data) != len(binData) {
		t.Fatalf("expected %d bytes, got %d", len(binData), len(data))
	}
	for i, b := range data {
		if b != binData[i] {
			t.Errorf("byte %d: expected 0x%02x, got 0x%02x", i, binData[i], b)
		}
	}
}

// --- ROT13 Tests ---

func TestROT13(t *testing.T) {
	c := &Base64Command{}
	params, _ := json.Marshal(base64Args{Action: "rot13", Input: "Hello World"})
	result := c.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Fatalf("ROT13 failed: %s", result.Output)
	}
	if !strings.Contains(result.Output, "Uryyb Jbeyq") {
		t.Errorf("expected 'Uryyb Jbeyq', got: %s", result.Output)
	}
}

func TestROT13Symmetric(t *testing.T) {
	c := &Base64Command{}
	// ROT13 applied twice should return original
	params, _ := json.Marshal(base64Args{Action: "rot13", Input: "Uryyb Jbeyq"})
	result := c.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Fatalf("ROT13 round-trip failed: %s", result.Output)
	}
	if !strings.Contains(result.Output, "Hello World") {
		t.Errorf("ROT13 not symmetric: expected 'Hello World', got: %s", result.Output)
	}
}

func TestROT13NonAlpha(t *testing.T) {
	c := &Base64Command{}
	params, _ := json.Marshal(base64Args{Action: "rot13", Input: "123!@#"})
	result := c.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Fatalf("ROT13 non-alpha failed: %s", result.Output)
	}
	if !strings.Contains(result.Output, "123!@#") {
		t.Errorf("ROT13 should not modify non-alpha chars, got: %s", result.Output)
	}
}

// --- URL Encode Tests ---

func TestURLEncode(t *testing.T) {
	c := &Base64Command{}
	params, _ := json.Marshal(base64Args{Action: "url", Input: "hello world&foo=bar"})
	result := c.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Fatalf("URL encode failed: %s", result.Output)
	}
	if !strings.Contains(result.Output, "hello+world%26foo%3Dbar") {
		t.Errorf("expected URL-encoded string, got: %s", result.Output)
	}
}

func TestURLDecode(t *testing.T) {
	c := &Base64Command{}
	params, _ := json.Marshal(base64Args{Action: "url-decode", Input: "hello+world%26foo%3Dbar"})
	result := c.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Fatalf("URL decode failed: %s", result.Output)
	}
	if !strings.Contains(result.Output, "hello world&foo=bar") {
		t.Errorf("expected decoded URL string, got: %s", result.Output)
	}
}

func TestURLDecodeInvalid(t *testing.T) {
	c := &Base64Command{}
	params, _ := json.Marshal(base64Args{Action: "url-decode", Input: "%ZZ"})
	result := c.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error for invalid URL encoding, got %s", result.Status)
	}
}

// --- Caesar Cipher Tests ---

func TestCaesarShift3(t *testing.T) {
	c := &Base64Command{}
	params, _ := json.Marshal(base64Args{Action: "caesar", Input: "Attack at dawn", Shift: 3})
	result := c.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Fatalf("Caesar failed: %s", result.Output)
	}
	if !strings.Contains(result.Output, "Dwwdfn dw gdzq") {
		t.Errorf("expected 'Dwwdfn dw gdzq', got: %s", result.Output)
	}
}

func TestCaesarNegativeShift(t *testing.T) {
	c := &Base64Command{}
	params, _ := json.Marshal(base64Args{Action: "caesar", Input: "Dwwdfn dw gdzq", Shift: -3})
	result := c.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Fatalf("Caesar decode failed: %s", result.Output)
	}
	if !strings.Contains(result.Output, "Attack at dawn") {
		t.Errorf("expected 'Attack at dawn', got: %s", result.Output)
	}
}

func TestCaesarMissingShift(t *testing.T) {
	c := &Base64Command{}
	params, _ := json.Marshal(base64Args{Action: "caesar", Input: "hello"})
	result := c.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error for missing shift, got %s", result.Status)
	}
}

func TestCaesarShift13IsROT13(t *testing.T) {
	c := &Base64Command{}
	// Caesar with shift 13 should produce same result as ROT13
	caesarParams, _ := json.Marshal(base64Args{Action: "caesar", Input: "Hello", Shift: 13})
	caesarResult := c.Execute(structs.Task{Params: string(caesarParams)})

	rot13Params, _ := json.Marshal(base64Args{Action: "rot13", Input: "Hello"})
	rot13Result := c.Execute(structs.Task{Params: string(rot13Params)})

	if caesarResult.Status != "success" || rot13Result.Status != "success" {
		t.Fatal("both should succeed")
	}
	// Both should contain "Uryyb"
	if !strings.Contains(caesarResult.Output, "Uryyb") {
		t.Errorf("Caesar shift 13 expected 'Uryyb', got: %s", caesarResult.Output)
	}
	if !strings.Contains(rot13Result.Output, "Uryyb") {
		t.Errorf("ROT13 expected 'Uryyb', got: %s", rot13Result.Output)
	}
}

func TestCaesarFileIO(t *testing.T) {
	c := &Base64Command{}
	dir := t.TempDir()
	inPath := filepath.Join(dir, "plain.txt")
	outPath := filepath.Join(dir, "shifted.txt")
	os.WriteFile(inPath, []byte("Secret Message"), 0644)

	params, _ := json.Marshal(base64Args{Action: "caesar", Input: inPath, File: true, Shift: 7, Output: outPath})
	result := c.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Fatalf("Caesar file I/O failed: %s", result.Output)
	}

	data, _ := os.ReadFile(outPath)
	if string(data) != "Zljyla Tlzzhnl" {
		t.Errorf("expected 'Zljyla Tlzzhnl', got '%s'", string(data))
	}
}

// --- parseXORKey Tests ---

func TestParseXORKeyString(t *testing.T) {
	key, err := parseXORKey("mykey")
	if err != nil {
		t.Fatal(err)
	}
	if string(key) != "mykey" {
		t.Errorf("expected 'mykey', got '%s'", string(key))
	}
}

func TestParseXORKeyHex(t *testing.T) {
	key, err := parseXORKey("0x41424344")
	if err != nil {
		t.Fatal(err)
	}
	if string(key) != "ABCD" {
		t.Errorf("expected 'ABCD', got '%s'", string(key))
	}
}

func TestParseXORKeyHexInvalid(t *testing.T) {
	_, err := parseXORKey("0xGG")
	if err == nil {
		t.Error("expected error for invalid hex key")
	}
}

// --- Unknown Action Test ---

func TestUnknownAction(t *testing.T) {
	c := &Base64Command{}
	params, _ := json.Marshal(base64Args{Action: "blowfish", Input: "test"})
	result := c.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error for unknown action, got %s", result.Status)
	}
	if !strings.Contains(result.Output, "unknown action") {
		t.Errorf("expected 'unknown action' message, got: %s", result.Output)
	}
}
