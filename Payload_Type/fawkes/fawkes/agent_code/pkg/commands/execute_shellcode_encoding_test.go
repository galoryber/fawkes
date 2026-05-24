package commands

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"testing"
)

func TestDecodeXOR_SingleByteKey(t *testing.T) {
	key := "ff"
	plaintext := []byte{0x90, 0x90, 0xCC} // NOP NOP INT3
	encoded := make([]byte, len(plaintext))
	for i, b := range plaintext {
		encoded[i] = b ^ 0xFF
	}

	decoded, err := decodeShellcode(encoded, "xor", key)
	if err != nil {
		t.Fatalf("decodeShellcode xor: %v", err)
	}
	if !bytes.Equal(decoded, plaintext) {
		t.Errorf("decoded = %x, want %x", decoded, plaintext)
	}
}

func TestDecodeXOR_MultiByteKey(t *testing.T) {
	key := "deadbeef"
	keyBytes, _ := hex.DecodeString(key)
	plaintext := []byte{0x48, 0x89, 0xe5, 0x48, 0x83, 0xec, 0x20, 0x90}
	encoded := make([]byte, len(plaintext))
	for i, b := range plaintext {
		encoded[i] = b ^ keyBytes[i%len(keyBytes)]
	}

	decoded, err := decodeShellcode(encoded, "xor", key)
	if err != nil {
		t.Fatalf("decodeShellcode xor: %v", err)
	}
	if !bytes.Equal(decoded, plaintext) {
		t.Errorf("decoded = %x, want %x", decoded, plaintext)
	}
}

func TestDecodeXOR_EmptyKey(t *testing.T) {
	_, err := decodeShellcode([]byte{0x90}, "xor", "")
	if err == nil {
		t.Error("xor with empty key should error")
	}
}

func TestDecodeXOR_InvalidHexKey(t *testing.T) {
	_, err := decodeShellcode([]byte{0x90}, "xor", "zzzz")
	if err == nil {
		t.Error("xor with invalid hex key should error")
	}
}

func TestDecodeXOR_RoundTrip(t *testing.T) {
	key := "4142434445"
	keyBytes, _ := hex.DecodeString(key)
	plaintext := make([]byte, 256)
	for i := range plaintext {
		plaintext[i] = byte(i)
	}

	encoded := make([]byte, len(plaintext))
	for i, b := range plaintext {
		encoded[i] = b ^ keyBytes[i%len(keyBytes)]
	}

	decoded, err := decodeShellcode(encoded, "xor", key)
	if err != nil {
		t.Fatalf("decodeShellcode xor: %v", err)
	}
	if !bytes.Equal(decoded, plaintext) {
		t.Errorf("round-trip failed: decoded length=%d, want %d", len(decoded), len(plaintext))
	}
}

func TestDecodeAES_RoundTrip(t *testing.T) {
	keyBytes := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, keyBytes); err != nil {
		t.Fatalf("rand: %v", err)
	}
	keyHex := hex.EncodeToString(keyBytes)

	plaintext := []byte{0x90, 0x90, 0xCC, 0x48, 0x89, 0xe5, 0xC3}

	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		t.Fatalf("rand: %v", err)
	}

	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		t.Fatalf("aes cipher: %v", err)
	}
	ciphertext := make([]byte, len(plaintext))
	cipher.NewCTR(block, iv).XORKeyStream(ciphertext, plaintext)

	encoded := append(iv, ciphertext...)

	decoded, err := decodeShellcode(encoded, "aes", keyHex)
	if err != nil {
		t.Fatalf("decodeShellcode aes: %v", err)
	}
	if !bytes.Equal(decoded, plaintext) {
		t.Errorf("aes round-trip failed: decoded=%x, want=%x", decoded, plaintext)
	}
}

func TestDecodeAES_WrongKeyLength(t *testing.T) {
	_, err := decodeShellcode(make([]byte, 32), "aes", "00112233")
	if err == nil {
		t.Error("aes with 4-byte key should error")
	}
}

func TestDecodeAES_TooShortCiphertext(t *testing.T) {
	keyHex := hex.EncodeToString(make([]byte, 32))
	_, err := decodeShellcode(make([]byte, 10), "aes", keyHex)
	if err == nil {
		t.Error("aes with ciphertext shorter than IV should error")
	}
}

func TestDecodeAES_EmptyKey(t *testing.T) {
	_, err := decodeShellcode(make([]byte, 32), "aes", "")
	if err == nil {
		t.Error("aes with empty key should error")
	}
}

func TestDecodeShellcode_None(t *testing.T) {
	data := []byte{0x90, 0x90, 0xCC}
	decoded, err := decodeShellcode(data, "none", "")
	if err != nil {
		t.Fatalf("none encoding should succeed: %v", err)
	}
	if !bytes.Equal(decoded, data) {
		t.Errorf("none encoding should return data unchanged")
	}
}

func TestDecodeShellcode_Empty(t *testing.T) {
	data := []byte{0x90, 0x90, 0xCC}
	decoded, err := decodeShellcode(data, "", "")
	if err != nil {
		t.Fatalf("empty encoding should succeed: %v", err)
	}
	if !bytes.Equal(decoded, data) {
		t.Errorf("empty encoding should return data unchanged")
	}
}

func TestDecodeShellcode_UnsupportedEncoding(t *testing.T) {
	_, err := decodeShellcode([]byte{0x90}, "rc4", "00")
	if err == nil {
		t.Error("unsupported encoding should error")
	}
}

func TestDecodeShellcodeArgs_JSON(t *testing.T) {
	input := `{"shellcode_b64":"kJDI","technique":"mmap","encoding":"xor","key":"ff"}`
	var args executeShellcodeArgs
	if err := json.Unmarshal([]byte(input), &args); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if args.Encoding != "xor" {
		t.Errorf("Encoding = %q, want %q", args.Encoding, "xor")
	}
	if args.Key != "ff" {
		t.Errorf("Key = %q, want %q", args.Key, "ff")
	}
	if args.ShellcodeB64 != "kJDI" {
		t.Errorf("ShellcodeB64 = %q, want %q", args.ShellcodeB64, "kJDI")
	}
	if args.Technique != "mmap" {
		t.Errorf("Technique = %q, want %q", args.Technique, "mmap")
	}
}

func TestEncodeXOR_RoundTrip(t *testing.T) {
	plaintext := []byte{0x48, 0x89, 0xe5, 0x48, 0x83, 0xec, 0x20, 0x90, 0xCC}
	encoded, keyHex, err := encodeData(plaintext, "xor")
	if err != nil {
		t.Fatalf("encodeData xor: %v", err)
	}
	if len(keyHex) != 64 {
		t.Fatalf("xor key should be 64 hex chars (32 bytes), got %d", len(keyHex))
	}
	if bytes.Equal(encoded, plaintext) {
		t.Fatal("encoded should differ from plaintext")
	}
	decoded, err := decodeShellcode(encoded, "xor", keyHex)
	if err != nil {
		t.Fatalf("decode xor: %v", err)
	}
	if !bytes.Equal(decoded, plaintext) {
		t.Errorf("round-trip failed: got %x, want %x", decoded, plaintext)
	}
}

func TestEncodeAES_RoundTrip(t *testing.T) {
	plaintext := []byte{0x48, 0x89, 0xe5, 0x48, 0x83, 0xec, 0x20, 0x90, 0xCC}
	encoded, keyHex, err := encodeData(plaintext, "aes")
	if err != nil {
		t.Fatalf("encodeData aes: %v", err)
	}
	if len(keyHex) != 64 {
		t.Fatalf("aes key should be 64 hex chars (32 bytes), got %d", len(keyHex))
	}
	if len(encoded) != aes.BlockSize+len(plaintext) {
		t.Fatalf("encoded should be IV (%d) + plaintext (%d) = %d, got %d",
			aes.BlockSize, len(plaintext), aes.BlockSize+len(plaintext), len(encoded))
	}
	decoded, err := decodeShellcode(encoded, "aes", keyHex)
	if err != nil {
		t.Fatalf("decode aes: %v", err)
	}
	if !bytes.Equal(decoded, plaintext) {
		t.Errorf("round-trip failed: got %x, want %x", decoded, plaintext)
	}
}

func TestEncodeXOR_UniqueKeys(t *testing.T) {
	data := []byte("test data")
	_, key1, _ := encodeData(data, "xor")
	_, key2, _ := encodeData(data, "xor")
	if key1 == key2 {
		t.Fatal("two encodes should produce different random keys")
	}
}

func TestEncodeAES_UniqueIV(t *testing.T) {
	data := []byte("test data")
	enc1, _, _ := encodeData(data, "aes")
	enc2, _, _ := encodeData(data, "aes")
	if bytes.Equal(enc1[:aes.BlockSize], enc2[:aes.BlockSize]) {
		t.Fatal("two encodes should produce different IVs")
	}
}

func TestEncodeData_UnsupportedEncoding(t *testing.T) {
	_, _, err := encodeData([]byte("test"), "rc4")
	if err == nil {
		t.Fatal("unsupported encoding should error")
	}
}

func TestEncodeXOR_LargeData(t *testing.T) {
	plaintext := make([]byte, 1024*1024)
	for i := range plaintext {
		plaintext[i] = byte(i % 256)
	}
	encoded, keyHex, err := encodeData(plaintext, "xor")
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	decoded, err := decodeShellcode(encoded, "xor", keyHex)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !bytes.Equal(decoded, plaintext) {
		t.Fatal("large data round-trip failed")
	}
}
