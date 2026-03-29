package http

import (
	"bytes"
	"crypto/aes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"fawkes/pkg/structs"
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
	encrypted, err := profile.encryptMessage(original, profile.EncryptionKey)
	if err != nil {
		t.Fatalf("encryptMessage failed: %v", err)
	}

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

	decrypted, err := profile.decryptResponse(withUUID, profile.EncryptionKey)
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
	encrypted, err := profile.encryptMessage(original, profile.EncryptionKey)
	if err != nil {
		t.Fatalf("encryptMessage failed: %v", err)
	}

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
	result, err := profile.decryptResponse(data, profile.EncryptionKey)
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
	_, err := profile.decryptResponse(short, profile.EncryptionKey)
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
	encrypted, err := profile.encryptMessage(original, profile.EncryptionKey)
	if err != nil {
		t.Fatalf("encryptMessage failed: %v", err)
	}

	// Prepend fake UUID and corrupt HMAC
	fakeUUID := []byte("12345678-1234-1234-1234-123456789012")
	withUUID := append(fakeUUID, encrypted...)
	// Corrupt last byte of HMAC
	withUUID[len(withUUID)-1] ^= 0xFF

	_, decErr := profile.decryptResponse(withUUID, profile.EncryptionKey)
	if decErr == nil {
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
	encrypted, err := profile.encryptMessage(original, profile.EncryptionKey)
	if err != nil {
		t.Fatalf("encryptMessage failed: %v", err)
	}

	fakeUUID := []byte("12345678-1234-1234-1234-123456789012")
	withUUID := append(fakeUUID, encrypted...)

	// Corrupt a ciphertext byte (not HMAC) — HMAC will fail first
	// This tests that malformed data is rejected
	if len(withUUID) > 60 {
		withUUID[55] ^= 0xFF
	}

	_, decErr := profile.decryptResponse(withUUID, profile.EncryptionKey)
	if decErr == nil {
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
	enc1, err := profile.encryptMessage(msg, profile.EncryptionKey)
	if err != nil {
		t.Fatalf("encryptMessage failed: %v", err)
	}
	enc2, err := profile.encryptMessage(msg, profile.EncryptionKey)
	if err != nil {
		t.Fatalf("encryptMessage failed: %v", err)
	}

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

	encrypted, err := profile.encryptMessage(original, profile.EncryptionKey)
	if err != nil {
		t.Fatalf("encryptMessage failed: %v", err)
	}
	fakeUUID := []byte("12345678-1234-1234-1234-123456789012")
	withUUID := append(fakeUUID, encrypted...)

	decrypted, err := profile.decryptResponse(withUUID, profile.EncryptionKey)
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
	_, err := profile.encryptMessage(msg, profile.EncryptionKey)
	// With invalid key, should return an error (never fall back to plaintext)
	if err == nil {
		t.Error("encryptMessage with invalid key should return an error")
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
		"",
		nil,
		nil,
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
		"",
		nil,
		nil,
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
		"",
		nil,
		nil,
	)

	if p.HostHeader != "fronted.example.com" {
		t.Errorf("HostHeader = %q, want %q", p.HostHeader, "fronted.example.com")
	}
}

func TestNewHTTPProfile_WithEncryptionKey(t *testing.T) {
	key := make([]byte, 32)
	keyB64 := base64.StdEncoding.EncodeToString(key)

	p := NewHTTPProfile(
		"http://localhost:80",
		"TestAgent/1.0",
		keyB64,
		10,
		5,
		10,
		true,
		"/get",
		"/post",
		"",
		"",
		"system-ca",
		"",
		nil,
		nil,
	)

	if p.EncryptionKey != keyB64 {
		t.Errorf("EncryptionKey not set correctly")
	}
	if !p.Debug {
		t.Error("Debug should be true")
	}
}

func TestNewHTTPProfile_InvalidProxy(t *testing.T) {
	// Invalid proxy URL should not crash — silently ignored
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
		"://not-a-valid-url",
		"none",
		"",
		nil,
		nil,
	)

	if p.client == nil {
		t.Error("client should not be nil even with invalid proxy")
	}
}

// --- getActiveUUID Tests ---

func TestGetActiveUUID_WithCallbackUUID(t *testing.T) {
	profile := &HTTPProfile{
		CallbackUUID: "callback-uuid-123",
	}
	agent := &structs.Agent{
		PayloadUUID: "payload-uuid-456",
	}

	result := profile.getActiveUUID(agent, nil)
	if result != "callback-uuid-123" {
		t.Errorf("getActiveUUID = %q, want callback UUID", result)
	}
}

func TestGetActiveUUID_WithoutCallbackUUID(t *testing.T) {
	profile := &HTTPProfile{
		CallbackUUID: "",
	}
	agent := &structs.Agent{
		PayloadUUID: "payload-uuid-456",
	}

	result := profile.getActiveUUID(agent, nil)
	if result != "payload-uuid-456" {
		t.Errorf("getActiveUUID = %q, want payload UUID", result)
	}
}

// --- encryptMessage edge cases ---

func TestEncryptMessage_WrongKeySizeBase64(t *testing.T) {
	// Valid base64 but decodes to wrong size for AES (not 16, 24, or 32 bytes)
	key := make([]byte, 17) // Not a valid AES key size
	keyB64 := base64.StdEncoding.EncodeToString(key)

	profile := &HTTPProfile{
		EncryptionKey: keyB64,
	}

	msg := []byte("test message")
	_, err := profile.encryptMessage(msg, profile.EncryptionKey)

	// With wrong key size, AES cipher creation fails — should return error (never plaintext)
	if err == nil {
		t.Error("encryptMessage with wrong key size should return an error")
	}
}

func TestEncryptDecrypt_MultipleBlockSizes(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 42)
	}
	keyB64 := base64.StdEncoding.EncodeToString(key)

	profile := &HTTPProfile{
		EncryptionKey: keyB64,
	}
	fakeUUID := []byte("12345678-1234-1234-1234-123456789012")

	// Test various message sizes including exact multiples of block size
	sizes := []int{1, 15, 16, 17, 31, 32, 33, 100, 255, 256, 1024}
	for _, size := range sizes {
		msg := make([]byte, size)
		for i := range msg {
			msg[i] = byte(i % 256)
		}

		encrypted, err := profile.encryptMessage(msg, profile.EncryptionKey)
		if err != nil {
			t.Fatalf("size %d: encryptMessage failed: %v", size, err)
		}
		withUUID := append(append([]byte{}, fakeUUID...), encrypted...)

		decrypted, err := profile.decryptResponse(withUUID, profile.EncryptionKey)
		if err != nil {
			t.Fatalf("size %d: decryptResponse failed: %v", size, err)
		}
		if !bytes.Equal(decrypted, msg) {
			t.Errorf("size %d: round-trip mismatch", size)
		}
	}
}

func TestDecryptResponse_InvalidEncryptionKeyBase64(t *testing.T) {
	profile := &HTTPProfile{
		EncryptionKey: "not-valid-base64!!!",
	}

	data := make([]byte, 100)
	_, err := profile.decryptResponse(data, profile.EncryptionKey)
	if err == nil {
		t.Error("decryptResponse with invalid base64 key should return error")
	}
}

func TestDecryptResponse_CiphertextNotBlockAligned(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	keyB64 := base64.StdEncoding.EncodeToString(key)

	profile := &HTTPProfile{
		EncryptionKey: keyB64,
	}

	// Create data with correct structure but ciphertext not aligned to block size
	// UUID (36) + IV (16) + ciphertext (not multiple of 16) + HMAC (32)
	// Total: 36 + 16 + 7 + 32 = 91
	data := make([]byte, 91)
	// Fill with valid-looking data
	copy(data[:36], []byte("12345678-1234-1234-1234-123456789012"))

	// Compute valid HMAC so it passes HMAC check (try both methods)
	// Actually, HMAC will fail regardless since data is random, so this tests
	// that the function doesn't panic on misaligned ciphertext
	_, err := profile.decryptResponse(data, profile.EncryptionKey)
	if err == nil {
		t.Error("decryptResponse with non-block-aligned ciphertext should fail")
	}
}

func TestDecryptResponse_EmptyCiphertext(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	keyB64 := base64.StdEncoding.EncodeToString(key)

	profile := &HTTPProfile{
		EncryptionKey: keyB64,
	}

	// Exactly 84 bytes: UUID (36) + IV (16) + no ciphertext (0) + HMAC (32)
	// This previously caused a panic on plaintext[len(plaintext)-1]
	data := make([]byte, 84)
	copy(data[:36], []byte("12345678-1234-1234-1234-123456789012"))

	_, err := profile.decryptResponse(data, profile.EncryptionKey)
	if err == nil {
		t.Error("decryptResponse with zero-length ciphertext should fail, not panic")
	}
}

// --- getString edge cases ---

func TestGetString_NilMap(t *testing.T) {
	// getString should handle nil gracefully
	var m map[string]interface{}
	if got := getString(m, "key"); got != "" {
		t.Errorf("getString on nil map = %q, want empty", got)
	}
}

func TestGetString_NilValue(t *testing.T) {
	m := map[string]interface{}{
		"key": nil,
	}
	if got := getString(m, "key"); got != "" {
		t.Errorf("getString for nil value = %q, want empty", got)
	}
}

// --- buildTLSConfig edge cases ---

func TestBuildTLSConfig_Empty(t *testing.T) {
	cfg := buildTLSConfig("")
	if !cfg.InsecureSkipVerify {
		t.Error("empty string should default to InsecureSkipVerify=true")
	}
}

func TestBuildTLSConfig_PinnedEmpty(t *testing.T) {
	cfg := buildTLSConfig("pinned:")
	// Empty fingerprint after "pinned:" should fall back
	if cfg.VerifyPeerCertificate != nil {
		t.Error("pinned with empty fingerprint should not set VerifyPeerCertificate")
	}
}

func TestBuildTLSConfig_PinnedUppercaseHex(t *testing.T) {
	// Valid SHA-256 fingerprint with uppercase hex
	fingerprint := "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"
	cfg := buildTLSConfig("pinned:" + fingerprint)
	// hex.DecodeString handles uppercase
	if cfg.VerifyPeerCertificate == nil {
		t.Error("pinned with uppercase hex should work")
	}
}

// --- Config Vault Tests ---

func TestSealConfig_EncryptsFields(t *testing.T) {
	profile := &HTTPProfile{
		BaseURL:       "http://c2.example.com:443",
		UserAgent:     "Mozilla/5.0 Test",
		EncryptionKey: "dGVzdGtleWJhc2U2NA==",
		CallbackUUID:  "test-uuid-1234",
		HostHeader:    "cdn.example.com",
		GetEndpoint:   "/api/get",
		PostEndpoint:  "/api/post",
		CustomHeaders: map[string]string{"X-Custom": "value"},
	}

	err := profile.SealConfig()
	if err != nil {
		t.Fatalf("SealConfig failed: %v", err)
	}

	// Struct fields should be zeroed
	if profile.BaseURL != "" {
		t.Errorf("BaseURL not zeroed: %q", profile.BaseURL)
	}
	if profile.UserAgent != "" {
		t.Errorf("UserAgent not zeroed: %q", profile.UserAgent)
	}
	if profile.EncryptionKey != "" {
		t.Errorf("EncryptionKey not zeroed: %q", profile.EncryptionKey)
	}
	if profile.CallbackUUID != "" {
		t.Errorf("CallbackUUID not zeroed: %q", profile.CallbackUUID)
	}
	if profile.HostHeader != "" {
		t.Errorf("HostHeader not zeroed: %q", profile.HostHeader)
	}
	if profile.CustomHeaders != nil {
		t.Errorf("CustomHeaders not nil")
	}

	// Vault should be active
	if !profile.IsSealed() {
		t.Error("IsSealed() should return true after SealConfig")
	}
}

func TestSealConfig_GetConfigReturnsOriginal(t *testing.T) {
	profile := &HTTPProfile{
		BaseURL:       "http://c2.example.com:443",
		UserAgent:     "Mozilla/5.0 Test",
		EncryptionKey: "dGVzdGtleWJhc2U2NA==",
		CallbackUUID:  "test-uuid-1234",
		HostHeader:    "cdn.example.com",
		GetEndpoint:   "/api/get",
		PostEndpoint:  "/api/post",
		CustomHeaders: map[string]string{"X-Custom": "value"},
	}

	err := profile.SealConfig()
	if err != nil {
		t.Fatalf("SealConfig failed: %v", err)
	}

	cfg := profile.getConfig()
	if cfg == nil {
		t.Fatal("getConfig returned nil")
	}

	if cfg.BaseURL != "http://c2.example.com:443" {
		t.Errorf("BaseURL = %q, want %q", cfg.BaseURL, "http://c2.example.com:443")
	}
	if cfg.UserAgent != "Mozilla/5.0 Test" {
		t.Errorf("UserAgent = %q, want %q", cfg.UserAgent, "Mozilla/5.0 Test")
	}
	if cfg.EncryptionKey != "dGVzdGtleWJhc2U2NA==" {
		t.Errorf("EncryptionKey = %q", cfg.EncryptionKey)
	}
	if cfg.CallbackUUID != "test-uuid-1234" {
		t.Errorf("CallbackUUID = %q", cfg.CallbackUUID)
	}
	if cfg.HostHeader != "cdn.example.com" {
		t.Errorf("HostHeader = %q", cfg.HostHeader)
	}
	if cfg.GetEndpoint != "/api/get" {
		t.Errorf("GetEndpoint = %q", cfg.GetEndpoint)
	}
	if cfg.PostEndpoint != "/api/post" {
		t.Errorf("PostEndpoint = %q", cfg.PostEndpoint)
	}
	if cfg.CustomHeaders["X-Custom"] != "value" {
		t.Errorf("CustomHeaders[X-Custom] = %q", cfg.CustomHeaders["X-Custom"])
	}
}

func TestSealConfig_GetConfigConcurrent(t *testing.T) {
	profile := &HTTPProfile{
		BaseURL:       "http://c2.example.com:443",
		EncryptionKey: "dGVzdGtleWJhc2U2NA==",
		PostEndpoint:  "/api/post",
	}
	if err := profile.SealConfig(); err != nil {
		t.Fatalf("SealConfig failed: %v", err)
	}

	// Multiple concurrent getConfig calls should be safe
	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func() {
			cfg := profile.getConfig()
			if cfg == nil || cfg.BaseURL != "http://c2.example.com:443" {
				t.Errorf("concurrent getConfig returned wrong data")
			}
			done <- true
		}()
	}
	for i := 0; i < 10; i++ {
		<-done
	}
}

func TestUpdateCallbackUUID_Sealed(t *testing.T) {
	profile := &HTTPProfile{
		CallbackUUID: "original-uuid",
		BaseURL:      "http://test:80",
	}
	if err := profile.SealConfig(); err != nil {
		t.Fatalf("SealConfig failed: %v", err)
	}

	profile.UpdateCallbackUUID("new-callback-uuid")

	cfg := profile.getConfig()
	if cfg.CallbackUUID != "new-callback-uuid" {
		t.Errorf("CallbackUUID = %q, want %q", cfg.CallbackUUID, "new-callback-uuid")
	}

	// Struct field should still be zeroed
	if profile.CallbackUUID != "" {
		t.Errorf("struct CallbackUUID should be empty: %q", profile.CallbackUUID)
	}
}

func TestUpdateCallbackUUID_Unsealed(t *testing.T) {
	profile := &HTTPProfile{CallbackUUID: "original"}
	profile.UpdateCallbackUUID("updated")
	if profile.CallbackUUID != "updated" {
		t.Errorf("CallbackUUID = %q, want %q", profile.CallbackUUID, "updated")
	}
}

func TestGetCallbackUUID_Sealed(t *testing.T) {
	profile := &HTTPProfile{
		CallbackUUID: "my-uuid",
		BaseURL:      "http://test:80",
	}
	if err := profile.SealConfig(); err != nil {
		t.Fatalf("SealConfig failed: %v", err)
	}

	got := profile.GetCallbackUUID()
	if got != "my-uuid" {
		t.Errorf("GetCallbackUUID = %q, want %q", got, "my-uuid")
	}
}

func TestGetCallbackUUID_Unsealed(t *testing.T) {
	profile := &HTTPProfile{CallbackUUID: "my-uuid"}
	if got := profile.GetCallbackUUID(); got != "my-uuid" {
		t.Errorf("GetCallbackUUID = %q, want %q", got, "my-uuid")
	}
}

func TestIsSealed_Default(t *testing.T) {
	profile := &HTTPProfile{}
	if profile.IsSealed() {
		t.Error("new profile should not be sealed")
	}
}

func TestGetConfig_Unsealed(t *testing.T) {
	profile := &HTTPProfile{
		BaseURL:   "http://test:80",
		UserAgent: "test-ua",
	}
	cfg := profile.getConfig()
	if cfg == nil {
		t.Fatal("getConfig should not return nil for unsealed profile")
	}
	if cfg.BaseURL != "http://test:80" {
		t.Errorf("BaseURL = %q", cfg.BaseURL)
	}
	if cfg.UserAgent != "test-ua" {
		t.Errorf("UserAgent = %q", cfg.UserAgent)
	}
}

func TestVaultEncryptDecrypt_RoundTrip(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	plaintext := []byte("sensitive C2 config data")

	encrypted := vaultEncrypt(key, plaintext)
	if encrypted == nil {
		t.Fatal("vaultEncrypt returned nil")
	}
	if bytes.Equal(encrypted, plaintext) {
		t.Error("encrypted should differ from plaintext")
	}

	decrypted := vaultDecrypt(key, encrypted)
	if decrypted == nil {
		t.Fatal("vaultDecrypt returned nil")
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("round-trip failed: got %q, want %q", string(decrypted), string(plaintext))
	}
}

func TestVaultDecrypt_WrongKey(t *testing.T) {
	key1 := make([]byte, 32)
	key2 := make([]byte, 32)
	for i := range key2 {
		key2[i] = byte(i + 1)
	}

	encrypted := vaultEncrypt(key1, []byte("secret"))
	decrypted := vaultDecrypt(key2, encrypted)
	if decrypted != nil {
		t.Error("decrypting with wrong key should return nil")
	}
}

func TestVaultZeroBytes(t *testing.T) {
	data := []byte("sensitive")
	vaultZeroBytes(data)
	for i, b := range data {
		if b != 0 {
			t.Errorf("byte %d not zeroed: %d", i, b)
		}
	}
}

func TestGetActiveUUID_WithConfig(t *testing.T) {
	profile := &HTTPProfile{}
	agent := &structs.Agent{PayloadUUID: "payload-uuid"}
	cfg := &sensitiveConfig{CallbackUUID: "cfg-callback-uuid"}

	result := profile.getActiveUUID(agent, cfg)
	if result != "cfg-callback-uuid" {
		t.Errorf("getActiveUUID = %q, want config's CallbackUUID", result)
	}
}

func TestGetActiveUUID_NilConfig(t *testing.T) {
	profile := &HTTPProfile{CallbackUUID: "struct-uuid"}
	agent := &structs.Agent{PayloadUUID: "payload-uuid"}

	result := profile.getActiveUUID(agent, nil)
	if result != "struct-uuid" {
		t.Errorf("getActiveUUID = %q, want struct CallbackUUID", result)
	}
}

func TestGetActiveUUID_EmptyConfigUUID(t *testing.T) {
	profile := &HTTPProfile{}
	agent := &structs.Agent{PayloadUUID: "payload-uuid"}
	cfg := &sensitiveConfig{CallbackUUID: ""}

	result := profile.getActiveUUID(agent, cfg)
	if result != "payload-uuid" {
		t.Errorf("getActiveUUID = %q, want payload UUID", result)
	}
}

// --- Fallback C2 URL Tests ---

func TestAllURLs_NoFallbacks(t *testing.T) {
	p := &HTTPProfile{BaseURL: "http://primary:80"}
	cfg := &sensitiveConfig{BaseURL: "http://primary:80"}
	urls := p.allURLs(cfg)
	if len(urls) != 1 || urls[0] != "http://primary:80" {
		t.Errorf("allURLs = %v, want [http://primary:80]", urls)
	}
}

func TestAllURLs_WithFallbacks(t *testing.T) {
	p := &HTTPProfile{}
	cfg := &sensitiveConfig{
		BaseURL:      "http://primary:80",
		FallbackURLs: []string{"http://backup1:80", "http://backup2:80"},
	}
	urls := p.allURLs(cfg)
	if len(urls) != 3 {
		t.Fatalf("allURLs returned %d URLs, want 3", len(urls))
	}
	if urls[0] != "http://primary:80" || urls[1] != "http://backup1:80" || urls[2] != "http://backup2:80" {
		t.Errorf("allURLs = %v, want [primary, backup1, backup2]", urls)
	}
}

func TestAllURLs_RotatesOnActiveIdx(t *testing.T) {
	p := &HTTPProfile{}
	p.activeURLIdx.Store(1)
	cfg := &sensitiveConfig{
		BaseURL:      "http://primary:80",
		FallbackURLs: []string{"http://backup1:80", "http://backup2:80"},
	}
	urls := p.allURLs(cfg)
	if len(urls) != 3 {
		t.Fatalf("allURLs returned %d URLs, want 3", len(urls))
	}
	// Should rotate so backup1 is first
	if urls[0] != "http://backup1:80" {
		t.Errorf("allURLs[0] = %q, want http://backup1:80 (rotated)", urls[0])
	}
	if urls[1] != "http://backup2:80" {
		t.Errorf("allURLs[1] = %q, want http://backup2:80", urls[1])
	}
	if urls[2] != "http://primary:80" {
		t.Errorf("allURLs[2] = %q, want http://primary:80", urls[2])
	}
}

func TestAllURLs_NilCfg(t *testing.T) {
	p := &HTTPProfile{
		BaseURL:      "http://struct:80",
		FallbackURLs: []string{"http://fb:80"},
	}
	urls := p.allURLs(nil)
	if len(urls) != 2 || urls[0] != "http://struct:80" || urls[1] != "http://fb:80" {
		t.Errorf("allURLs with nil cfg = %v, want [struct, fb]", urls)
	}
}

func TestMakeRequest_FailoverToBackup(t *testing.T) {
	// Primary server is down, backup responds
	hitCount := 0
	backup := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hitCount++
		w.WriteHeader(200)
		fmt.Fprint(w, "ok")
	}))
	defer backup.Close()

	p := NewHTTPProfile(
		"http://127.0.0.1:1", // unreachable port
		"TestAgent/1.0",
		"",
		1, 5, 0, false,
		"/test", "/test",
		"", "", "none", "",
		[]string{backup.URL}, // fallback,
		nil,
	)

	cfg := &sensitiveConfig{
		BaseURL:      "http://127.0.0.1:1",
		FallbackURLs: []string{backup.URL},
		UserAgent:    "TestAgent/1.0",
	}

	resp, err := p.makeRequest("GET", "/test", nil, cfg)
	if err != nil {
		t.Fatalf("makeRequest should succeed via fallback, got: %v", err)
	}
	resp.Body.Close()
	if hitCount != 1 {
		t.Errorf("backup hit count = %d, want 1", hitCount)
	}
	// activeURLIdx should have been updated
	if p.activeURLIdx.Load() == 0 {
		t.Error("activeURLIdx should have been updated to fallback")
	}
}

func TestMakeRequest_AllFail(t *testing.T) {
	p := NewHTTPProfile(
		"http://127.0.0.1:1",
		"TestAgent/1.0",
		"",
		1, 5, 0, false,
		"/test", "/test",
		"", "", "none", "",
		[]string{"http://127.0.0.1:2"},
		nil,
	)

	cfg := &sensitiveConfig{
		BaseURL:      "http://127.0.0.1:1",
		FallbackURLs: []string{"http://127.0.0.1:2"},
		UserAgent:    "TestAgent/1.0",
	}

	_, err := p.makeRequest("GET", "/test", nil, cfg)
	if err == nil {
		t.Fatal("makeRequest should fail when all URLs unreachable")
	}
}

func TestNewHTTPProfile_WithFallbackURLs(t *testing.T) {
	fallbacks := []string{"http://backup1:80", "http://backup2:80"}
	p := NewHTTPProfile(
		"http://primary:80",
		"TestAgent/1.0",
		"",
		10, 5, 10, false,
		"/get", "/post",
		"", "", "none", "",
		fallbacks,
		nil,
	)

	if len(p.FallbackURLs) != 2 {
		t.Fatalf("FallbackURLs = %v, want 2 entries", p.FallbackURLs)
	}
	if p.FallbackURLs[0] != "http://backup1:80" {
		t.Errorf("FallbackURLs[0] = %q, want http://backup1:80", p.FallbackURLs[0])
	}
}

func TestMakeRequest_ConcurrentFailover(t *testing.T) {
	// Verify no data race when multiple goroutines call makeRequest concurrently
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		fmt.Fprint(w, "ok")
	}))
	defer server.Close()

	p := NewHTTPProfile(
		server.URL,
		"TestAgent/1.0",
		"",
		1, 5, 0, false,
		"/test", "/test",
		"", "", "none", "",
		[]string{server.URL + "/fb1", server.URL + "/fb2"},
		nil,
	)

	cfg := &sensitiveConfig{
		BaseURL:      server.URL,
		FallbackURLs: []string{server.URL + "/fb1", server.URL + "/fb2"},
		UserAgent:    "TestAgent/1.0",
	}

	// Launch concurrent requests — race detector will catch unsynchronized access
	done := make(chan error, 20)
	for i := 0; i < 20; i++ {
		go func() {
			resp, err := p.makeRequest("GET", "/test", nil, cfg)
			if err != nil {
				done <- err
				return
			}
			resp.Body.Close()
			done <- nil
		}()
	}
	for i := 0; i < 20; i++ {
		if err := <-done; err != nil {
			t.Errorf("concurrent makeRequest failed: %v", err)
		}
	}
}

func TestSealConfig_PreservesFallbackURLs(t *testing.T) {
	p := NewHTTPProfile(
		"http://primary:80",
		"TestAgent/1.0",
		"",
		10, 5, 10, false,
		"/get", "/post",
		"", "", "none", "",
		[]string{"http://backup:80"},
		nil,
	)

	if err := p.SealConfig(); err != nil {
		t.Fatalf("SealConfig failed: %v", err)
	}

	cfg := p.getConfig()
	if cfg == nil {
		t.Fatal("getConfig returned nil after seal")
	}
	if cfg.BaseURL != "http://primary:80" {
		t.Errorf("BaseURL = %q after seal, want http://primary:80", cfg.BaseURL)
	}
	if len(cfg.FallbackURLs) != 1 || cfg.FallbackURLs[0] != "http://backup:80" {
		t.Errorf("FallbackURLs = %v after seal, want [http://backup:80]", cfg.FallbackURLs)
	}
	// Struct fields should be zeroed
	if p.BaseURL != "" {
		t.Error("BaseURL should be zeroed after seal")
	}
	if p.FallbackURLs != nil {
		t.Error("FallbackURLs should be nil after seal")
	}
}

// --- URI Token Resolution Tests ---

func TestResolveURITokens_NoTokens(t *testing.T) {
	// Path without tokens should be returned unchanged
	path := "/api/v1/status"
	got := resolveURITokens(path)
	if got != path {
		t.Errorf("resolveURITokens(%q) = %q, want unchanged", path, got)
	}
}

func TestResolveURITokens_RandToken(t *testing.T) {
	path := "/api/{rand:8}/check"
	got := resolveURITokens(path)
	if got == path {
		t.Error("resolveURITokens should replace {rand:8} token")
	}
	// Should have exactly 8 hex chars in the middle
	parts := strings.SplitN(got, "/", 4)
	if len(parts) != 4 {
		t.Fatalf("expected 4 path segments, got %d: %q", len(parts), got)
	}
	if len(parts[2]) != 8 {
		t.Errorf("random segment length = %d, want 8: %q", len(parts[2]), parts[2])
	}
	// Each call should produce different output
	got2 := resolveURITokens(path)
	if got == got2 {
		t.Error("resolveURITokens should produce different output each call")
	}
}

func TestResolveURITokens_IntToken(t *testing.T) {
	path := "/api/v{int:1-3}/data"
	seen := make(map[string]bool)
	for i := 0; i < 50; i++ {
		got := resolveURITokens(path)
		// Extract the version number
		parts := strings.SplitN(got, "/", 4)
		if len(parts) != 4 {
			t.Fatalf("expected 4 path segments, got %d: %q", len(parts), got)
		}
		ver := strings.TrimPrefix(parts[2], "v")
		seen[ver] = true
		if ver != "1" && ver != "2" && ver != "3" {
			t.Errorf("version = %q, want 1, 2, or 3", ver)
		}
	}
	if len(seen) < 2 {
		t.Errorf("expected variety in random ints, only saw: %v", seen)
	}
}

func TestResolveURITokens_MultipleTokens(t *testing.T) {
	path := "/v{int:1-5}/{rand:4}/status"
	got := resolveURITokens(path)
	if strings.Contains(got, "{") {
		t.Errorf("unresolved tokens remain: %q", got)
	}
}

func TestResolveURITokens_Empty(t *testing.T) {
	got := resolveURITokens("")
	if got != "" {
		t.Errorf("resolveURITokens(\"\") = %q, want empty", got)
	}
}
