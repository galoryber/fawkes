package agentfunctions

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func TestEnvDeriveEncrypt_RoundTrip(t *testing.T) {
	key := sha256.Sum256([]byte("test-key"))
	plaintext := []byte(`{"callbackHost":"http://c2.test.com","payloadUUID":"uuid-123"}`)

	encrypted, err := envDeriveEncrypt(key[:], plaintext)
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}

	if strings.Contains(string(encrypted), "callbackHost") {
		t.Fatal("encrypted data should not contain plaintext")
	}

	if len(encrypted) < 12+16+len(plaintext) {
		t.Fatalf("encrypted too short: got %d bytes", len(encrypted))
	}
}

func TestEnvDeriveEncrypt_DifferentNonce(t *testing.T) {
	key := sha256.Sum256([]byte("test-key"))
	plaintext := []byte("same plaintext")

	enc1, _ := envDeriveEncrypt(key[:], plaintext)
	enc2, _ := envDeriveEncrypt(key[:], plaintext)

	if string(enc1) == string(enc2) {
		t.Fatal("two encryptions should produce different ciphertext (random nonce)")
	}
}

func TestRemoveLdflag_Simple(t *testing.T) {
	ldflags := "-s -w -X 'main.payloadUUID=abc' -X 'main.callbackHost=http://test'"
	result := removeLdflag(ldflags, "main", "payloadUUID")
	if strings.Contains(result, "payloadUUID") {
		t.Fatalf("payloadUUID should be removed: %q", result)
	}
	if !strings.Contains(result, "callbackHost") {
		t.Fatal("callbackHost should remain")
	}
}

func TestRemoveLdflag_NotPresent(t *testing.T) {
	ldflags := "-s -w -X 'main.callbackHost=http://test'"
	result := removeLdflag(ldflags, "main", "notHere")
	if result != ldflags {
		t.Fatalf("should be unchanged: got %q, want %q", result, ldflags)
	}
}

func TestRemoveLdflag_PreservesOthers(t *testing.T) {
	ldflags := "-X 'pkg.a=1' -X 'pkg.b=2' -X 'pkg.c=3'"
	result := removeLdflag(ldflags, "pkg", "b")
	if strings.Contains(result, "pkg.b=") {
		t.Fatalf("b should be removed: %q", result)
	}
	if !strings.Contains(result, "pkg.a=1") || !strings.Contains(result, "pkg.c=3") {
		t.Fatalf("a and c should remain: %q", result)
	}
}

func TestRemoveLdflag_AllSensitive(t *testing.T) {
	ldflags := "-s -w"
	for _, v := range sensitiveConfigVars {
		ldflags += " -X 'main." + v + "=val_" + v + "'"
	}
	ldflags += " -X 'main.sleepInterval=10'"

	for _, v := range sensitiveConfigVars {
		ldflags = removeLdflag(ldflags, "main", v)
	}

	for _, v := range sensitiveConfigVars {
		if strings.Contains(ldflags, v) {
			t.Fatalf("%s should be removed: %q", v, ldflags)
		}
	}
	if !strings.Contains(ldflags, "sleepInterval") {
		t.Fatal("non-sensitive sleepInterval should remain")
	}
}

func TestSensitiveConfigVars_Coverage(t *testing.T) {
	expected := map[string]bool{
		"payloadUUID": true, "callbackHost": true, "callbackPort": true,
		"userAgent": true, "userAgentPool": true, "encryptionKey": true,
		"getURI": true, "postURI": true, "hostHeader": true,
		"proxyURL": true, "proxyUser": true, "proxyPass": true,
		"proxyDomain": true, "customHeaders": true, "fallbackHosts": true,
		"contentTypes": true, "trafficProfile": true,
		"discordBotToken": true, "discordChannelID": true,
		"httpxConfig": true, "httpxDomains": true,
		"mtlsCertPEM": true, "mtlsKeyPEM": true, "xorKey": true,
	}

	for _, v := range sensitiveConfigVars {
		if !expected[v] {
			t.Errorf("sensitiveConfigVars has unexpected entry: %s", v)
		}
		delete(expected, v)
	}

	for v := range expected {
		t.Errorf("sensitiveConfigVars missing entry: %s", v)
	}
}

func TestEnvDeriveKeyDerivation_SeedFormat(t *testing.T) {
	tests := []struct {
		components []string
		expected   string
	}{
		{[]string{"testhost"}, "fawkes-env-derive:testhost"},
		{[]string{"myhost", "mydomain"}, "fawkes-env-derive:myhost:mydomain"},
		{[]string{"host", "dom", "user"}, "fawkes-env-derive:host:dom:user"},
	}

	for _, tt := range tests {
		seed := "fawkes-env-derive:" + strings.Join(tt.components, ":")
		if seed != tt.expected {
			t.Errorf("seed mismatch: got %q, want %q", seed, tt.expected)
		}
	}
}

func TestEnvDeriveEndToEnd_EncryptDecrypt(t *testing.T) {
	hostname := "target-pc"
	seed := "fawkes-env-derive:" + strings.ToLower(strings.TrimSpace(hostname))
	key := sha256.Sum256([]byte(seed))

	configMap := map[string]string{
		"payloadUUID":   "uuid-abc-123",
		"callbackHost":  "http://192.168.100.184",
		"callbackPort":  "443",
		"encryptionKey": "aes256key-goes-here",
		"getURI":        "/api/v1/data",
		"postURI":       "/api/v1/submit",
	}
	jsonBytes, _ := json.Marshal(configMap)

	encrypted, err := envDeriveEncrypt(key[:], jsonBytes)
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}

	blob := base64.StdEncoding.EncodeToString(encrypted)

	// Correct key → successful decrypt
	ciphertext, _ := base64.StdEncoding.DecodeString(blob)
	block, _ := aes.NewCipher(key[:])
	gcm, _ := cipher.NewGCM(block)
	nonce, ct := ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		t.Fatalf("correct key decrypt failed: %v", err)
	}

	var recovered map[string]string
	if err := json.Unmarshal(plaintext, &recovered); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if recovered["payloadUUID"] != "uuid-abc-123" {
		t.Fatalf("payloadUUID mismatch: %q", recovered["payloadUUID"])
	}
	if recovered["callbackHost"] != "http://192.168.100.184" {
		t.Fatalf("callbackHost mismatch: %q", recovered["callbackHost"])
	}

	// Wrong key → decrypt fails
	wrongKey := sha256.Sum256([]byte("fawkes-env-derive:wrong-host"))
	wrongBlock, _ := aes.NewCipher(wrongKey[:])
	wrongGCM, _ := cipher.NewGCM(wrongBlock)
	_, wrongErr := wrongGCM.Open(nil, nonce, ct, nil)
	if wrongErr == nil {
		t.Fatal("wrong key should fail to decrypt")
	}
}
