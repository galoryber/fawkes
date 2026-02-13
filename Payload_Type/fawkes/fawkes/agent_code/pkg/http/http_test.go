package http

import (
	"bytes"
	"crypto/aes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"testing"
)

// --- pkcs7Pad Tests ---

func TestPkcs7Pad_Basic(t *testing.T) {
	data := []byte("hello")
	padded, err := pkcs7Pad(data, aes.BlockSize)
	if err != nil {
		t.Fatalf("pkcs7Pad failed: %v", err)
	}
	if len(padded)%aes.BlockSize != 0 {
		t.Errorf("padded length %d is not multiple of block size %d", len(padded), aes.BlockSize)
	}
	// "hello" is 5 bytes, needs 11 bytes of padding to reach 16
	if len(padded) != 16 {
		t.Errorf("padded length = %d, want 16", len(padded))
	}
	// Last byte should be padding value (11)
	if padded[len(padded)-1] != 11 {
		t.Errorf("last padding byte = %d, want 11", padded[len(padded)-1])
	}
}

func TestPkcs7Pad_ExactBlockSize(t *testing.T) {
	data := make([]byte, aes.BlockSize) // 16 bytes exactly
	padded, err := pkcs7Pad(data, aes.BlockSize)
	if err != nil {
		t.Fatalf("pkcs7Pad failed: %v", err)
	}
	// Full block of padding should be added
	if len(padded) != 2*aes.BlockSize {
		t.Errorf("padded length = %d, want %d", len(padded), 2*aes.BlockSize)
	}
	// Last byte should be 16 (full block padding)
	if padded[len(padded)-1] != byte(aes.BlockSize) {
		t.Errorf("last padding byte = %d, want %d", padded[len(padded)-1], aes.BlockSize)
	}
}

func TestPkcs7Pad_SingleByte(t *testing.T) {
	data := []byte("A")
	padded, err := pkcs7Pad(data, aes.BlockSize)
	if err != nil {
		t.Fatalf("pkcs7Pad failed: %v", err)
	}
	if len(padded) != aes.BlockSize {
		t.Errorf("padded length = %d, want %d", len(padded), aes.BlockSize)
	}
	// 15 bytes of padding
	if padded[len(padded)-1] != 15 {
		t.Errorf("last padding byte = %d, want 15", padded[len(padded)-1])
	}
}

func TestPkcs7Pad_EmptyData(t *testing.T) {
	_, err := pkcs7Pad(nil, aes.BlockSize)
	if err == nil {
		t.Error("pkcs7Pad(nil) should return error")
	}

	_, err = pkcs7Pad([]byte{}, aes.BlockSize)
	if err == nil {
		t.Error("pkcs7Pad(empty) should return error")
	}
}

func TestPkcs7Pad_InvalidBlockSize(t *testing.T) {
	_, err := pkcs7Pad([]byte("test"), 0)
	if err == nil {
		t.Error("pkcs7Pad with blockSize 0 should return error")
	}

	_, err = pkcs7Pad([]byte("test"), -1)
	if err == nil {
		t.Error("pkcs7Pad with blockSize -1 should return error")
	}
}

func TestPkcs7Pad_AllPaddingBytesCorrect(t *testing.T) {
	data := []byte("test") // 4 bytes, needs 12 padding
	padded, err := pkcs7Pad(data, aes.BlockSize)
	if err != nil {
		t.Fatalf("pkcs7Pad failed: %v", err)
	}
	paddingLen := int(padded[len(padded)-1])
	for i := len(padded) - paddingLen; i < len(padded); i++ {
		if padded[i] != byte(paddingLen) {
			t.Errorf("padding byte at index %d = %d, want %d", i, padded[i], paddingLen)
		}
	}
}

// --- Encrypt/Decrypt Round-Trip Tests ---

func TestEncryptDecrypt_RoundTrip(t *testing.T) {
	// Generate a test AES-256 key (32 bytes)
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	keyB64 := base64.StdEncoding.EncodeToString(key)

	profile := &HTTPProfile{
		EncryptionKey: keyB64,
	}

	original := []byte(`{"action":"checkin","uuid":"test-uuid-1234"}`)
	encrypted := profile.encryptMessage(original)

	if bytes.Equal(encrypted, original) {
		t.Error("encrypted message should differ from original")
	}

	// Encrypted format: IV (16) + Ciphertext + HMAC (32)
	if len(encrypted) < 16+32 {
		t.Fatalf("encrypted message too short: %d bytes", len(encrypted))
	}

	// Decrypt: prepend a fake 36-byte UUID to match expected format
	fakeUUID := []byte("12345678-1234-1234-1234-123456789012")
	withUUID := append(fakeUUID, encrypted...)

	decrypted, err := profile.decryptResponse(withUUID)
	if err != nil {
		t.Fatalf("decryptResponse failed: %v", err)
	}

	if !bytes.Equal(decrypted, original) {
		t.Errorf("decrypted = %q, want %q", string(decrypted), string(original))
	}
}

func TestEncryptDecrypt_EmptyKey(t *testing.T) {
	profile := &HTTPProfile{
		EncryptionKey: "",
	}

	original := []byte("test message")
	encrypted := profile.encryptMessage(original)

	// With no key, message should pass through unchanged
	if !bytes.Equal(encrypted, original) {
		t.Error("with empty key, encryptMessage should return original")
	}
}

func TestDecryptResponse_EmptyKey(t *testing.T) {
	profile := &HTTPProfile{
		EncryptionKey: "",
	}

	data := []byte("test data")
	result, err := profile.decryptResponse(data)
	if err != nil {
		t.Fatalf("decryptResponse with empty key should not error: %v", err)
	}
	if !bytes.Equal(result, data) {
		t.Error("with empty key, decryptResponse should return original data")
	}
}

func TestDecryptResponse_TooShort(t *testing.T) {
	key := make([]byte, 32)
	keyB64 := base64.StdEncoding.EncodeToString(key)

	profile := &HTTPProfile{
		EncryptionKey: keyB64,
	}

	// Less than 36 (UUID) + 16 (IV) + 32 (HMAC) = 84 bytes
	short := make([]byte, 50)
	_, err := profile.decryptResponse(short)
	if err == nil {
		t.Error("decryptResponse should fail on data too short")
	}
}

func TestDecryptResponse_InvalidHMAC(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	keyB64 := base64.StdEncoding.EncodeToString(key)

	profile := &HTTPProfile{
		EncryptionKey: keyB64,
	}

	original := []byte("test message for HMAC verification")
	encrypted := profile.encryptMessage(original)

	// Prepend fake UUID and corrupt HMAC
	fakeUUID := []byte("12345678-1234-1234-1234-123456789012")
	withUUID := append(fakeUUID, encrypted...)
	// Corrupt last byte of HMAC
	withUUID[len(withUUID)-1] ^= 0xFF

	_, err := profile.decryptResponse(withUUID)
	if err == nil {
		t.Error("decryptResponse should fail with corrupted HMAC")
	}
}

func TestDecryptResponse_InvalidPadding(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	keyB64 := base64.StdEncoding.EncodeToString(key)

	profile := &HTTPProfile{
		EncryptionKey: keyB64,
	}

	original := []byte("test")
	encrypted := profile.encryptMessage(original)

	fakeUUID := []byte("12345678-1234-1234-1234-123456789012")
	withUUID := append(fakeUUID, encrypted...)

	// Corrupt a ciphertext byte (not HMAC) — HMAC will fail first
	// This tests that malformed data is rejected
	if len(withUUID) > 60 {
		withUUID[55] ^= 0xFF
	}

	_, err := profile.decryptResponse(withUUID)
	if err == nil {
		t.Error("decryptResponse should fail with corrupted ciphertext")
	}
}

func TestEncryptMessage_DifferentEachTime(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	keyB64 := base64.StdEncoding.EncodeToString(key)

	profile := &HTTPProfile{
		EncryptionKey: keyB64,
	}

	msg := []byte("same message")
	enc1 := profile.encryptMessage(msg)
	enc2 := profile.encryptMessage(msg)

	// Due to random IV, the two encrypted messages should differ
	if bytes.Equal(enc1, enc2) {
		t.Error("encrypting same message twice should produce different ciphertexts (random IV)")
	}
}

func TestEncryptDecrypt_LargeMessage(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i * 3)
	}
	keyB64 := base64.StdEncoding.EncodeToString(key)

	profile := &HTTPProfile{
		EncryptionKey: keyB64,
	}

	// Large message (multiple AES blocks)
	original := make([]byte, 4096)
	for i := range original {
		original[i] = byte(i % 256)
	}

	encrypted := profile.encryptMessage(original)
	fakeUUID := []byte("12345678-1234-1234-1234-123456789012")
	withUUID := append(fakeUUID, encrypted...)

	decrypted, err := profile.decryptResponse(withUUID)
	if err != nil {
		t.Fatalf("decryptResponse for large message failed: %v", err)
	}

	if !bytes.Equal(decrypted, original) {
		t.Error("large message round-trip failed")
	}
}

func TestEncryptDecrypt_InvalidKey(t *testing.T) {
	profile := &HTTPProfile{
		EncryptionKey: "not-valid-base64!!!",
	}

	msg := []byte("test")
	result := profile.encryptMessage(msg)
	// With invalid key, should return original message
	if !bytes.Equal(result, msg) {
		t.Error("encryptMessage with invalid key should return original message")
	}
}

// --- buildTLSConfig Tests ---

func TestBuildTLSConfig_None(t *testing.T) {
	cfg := buildTLSConfig("none")
	if !cfg.InsecureSkipVerify {
		t.Error("'none' mode should set InsecureSkipVerify=true")
	}
}

func TestBuildTLSConfig_Unrecognized(t *testing.T) {
	cfg := buildTLSConfig("something-unknown")
	if !cfg.InsecureSkipVerify {
		t.Error("unrecognized mode should default to InsecureSkipVerify=true")
	}
}

func TestBuildTLSConfig_SystemCA(t *testing.T) {
	cfg := buildTLSConfig("system-ca")
	if cfg.InsecureSkipVerify {
		t.Error("'system-ca' mode should not skip verification")
	}
	if cfg.MinVersion != 0x0303 { // tls.VersionTLS12
		t.Errorf("MinVersion = %x, want TLS 1.2 (0x0303)", cfg.MinVersion)
	}
}

func TestBuildTLSConfig_PinnedValid(t *testing.T) {
	// Valid SHA-256 fingerprint (64 hex chars = 32 bytes)
	fingerprint := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	cfg := buildTLSConfig("pinned:" + fingerprint)

	if !cfg.InsecureSkipVerify {
		t.Error("pinned mode should set InsecureSkipVerify=true (custom verification)")
	}
	if cfg.VerifyPeerCertificate == nil {
		t.Error("pinned mode should set VerifyPeerCertificate callback")
	}
}

func TestBuildTLSConfig_PinnedInvalidHex(t *testing.T) {
	cfg := buildTLSConfig("pinned:not-valid-hex")
	if !cfg.InsecureSkipVerify {
		t.Error("invalid pinned fingerprint should fall back to InsecureSkipVerify")
	}
	if cfg.VerifyPeerCertificate != nil {
		t.Error("invalid fingerprint should not set VerifyPeerCertificate")
	}
}

func TestBuildTLSConfig_PinnedWrongLength(t *testing.T) {
	// Valid hex but wrong length (not 32 bytes)
	cfg := buildTLSConfig("pinned:aabbccdd")
	if cfg.VerifyPeerCertificate != nil {
		t.Error("wrong-length fingerprint should not set VerifyPeerCertificate")
	}
}

func TestBuildTLSConfig_PinnedVerifyCallback(t *testing.T) {
	// Create a "certificate" and compute its SHA-256
	certData := []byte("fake certificate data for testing")
	hash := sha256.Sum256(certData)
	fingerprint := hex.EncodeToString(hash[:])

	cfg := buildTLSConfig("pinned:" + fingerprint)

	// Should accept matching cert
	err := cfg.VerifyPeerCertificate([][]byte{certData}, nil)
	if err != nil {
		t.Errorf("VerifyPeerCertificate should accept matching cert, got: %v", err)
	}

	// Should reject non-matching cert
	err = cfg.VerifyPeerCertificate([][]byte{[]byte("wrong cert")}, nil)
	if err == nil {
		t.Error("VerifyPeerCertificate should reject non-matching cert")
	}

	// Should reject empty cert list
	err = cfg.VerifyPeerCertificate([][]byte{}, nil)
	if err == nil {
		t.Error("VerifyPeerCertificate should reject empty cert list")
	}
}

// --- getString Tests ---

func TestGetString_Exists(t *testing.T) {
	m := map[string]interface{}{
		"key1": "value1",
		"key2": 42,
	}

	if got := getString(m, "key1"); got != "value1" {
		t.Errorf("getString = %q, want %q", got, "value1")
	}
}

func TestGetString_Missing(t *testing.T) {
	m := map[string]interface{}{}
	if got := getString(m, "missing"); got != "" {
		t.Errorf("getString for missing key = %q, want empty", got)
	}
}

func TestGetString_NonStringValue(t *testing.T) {
	m := map[string]interface{}{
		"number": 42,
		"bool":   true,
	}

	if got := getString(m, "number"); got != "" {
		t.Errorf("getString for number value = %q, want empty", got)
	}
	if got := getString(m, "bool"); got != "" {
		t.Errorf("getString for bool value = %q, want empty", got)
	}
}

// --- NewHTTPProfile Tests ---

func TestNewHTTPProfile_BasicConfig(t *testing.T) {
	p := NewHTTPProfile(
		"http://localhost:80",
		"TestAgent/1.0",
		"",
		10,
		5,
		10,
		false,
		"/get",
		"/post",
		"",
		"",
		"none",
	)

	if p.BaseURL != "http://localhost:80" {
		t.Errorf("BaseURL = %q, want %q", p.BaseURL, "http://localhost:80")
	}
	if p.UserAgent != "TestAgent/1.0" {
		t.Errorf("UserAgent = %q, want %q", p.UserAgent, "TestAgent/1.0")
	}
	if p.MaxRetries != 10 {
		t.Errorf("MaxRetries = %d, want 10", p.MaxRetries)
	}
	if p.client == nil {
		t.Error("client should not be nil")
	}
}

func TestNewHTTPProfile_WithProxy(t *testing.T) {
	p := NewHTTPProfile(
		"http://localhost:80",
		"TestAgent/1.0",
		"",
		10,
		5,
		10,
		false,
		"/get",
		"/post",
		"",
		"http://proxy:8080",
		"none",
	)

	if p.client == nil {
		t.Error("client should not be nil even with proxy")
	}
}

func TestNewHTTPProfile_WithHostHeader(t *testing.T) {
	p := NewHTTPProfile(
		"http://realserver:80",
		"TestAgent/1.0",
		"",
		10,
		5,
		10,
		false,
		"/get",
		"/post",
		"fronted.example.com",
		"",
		"none",
	)

	if p.HostHeader != "fronted.example.com" {
		t.Errorf("HostHeader = %q, want %q", p.HostHeader, "fronted.example.com")
	}
}
