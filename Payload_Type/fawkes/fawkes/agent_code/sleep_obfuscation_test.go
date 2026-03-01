package main

import (
	"bytes"
	"crypto/rand"
	"testing"

	"fawkes/pkg/commands"
	fhttp "fawkes/pkg/http"
	"fawkes/pkg/profiles"
	"fawkes/pkg/structs"
)

// --- sleepEncrypt / sleepDecrypt tests ---

func TestSleepEncryptDecryptRoundTrip(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name      string
		plaintext []byte
	}{
		{"short", []byte("hello")},
		{"json-like", []byte(`{"u":"abc-123","d":"CONTOSO","h":"WORKSTATION"}`)},
		{"binary", bytes.Repeat([]byte{0x00, 0xFF, 0xAB}, 100)},
		{"single-byte", []byte{0x42}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ct := sleepEncrypt(key, tc.plaintext)
			if ct == nil {
				t.Fatal("sleepEncrypt returned nil")
			}
			// Ciphertext must differ from plaintext
			if bytes.Equal(ct, tc.plaintext) && len(tc.plaintext) > 0 {
				t.Error("ciphertext should differ from plaintext")
			}
			pt := sleepDecrypt(key, ct)
			if pt == nil {
				t.Fatal("sleepDecrypt returned nil")
			}
			if !bytes.Equal(pt, tc.plaintext) {
				t.Errorf("round-trip mismatch: got %q, want %q", pt, tc.plaintext)
			}
		})
	}
}

func TestSleepDecryptWrongKey(t *testing.T) {
	key1 := make([]byte, 32)
	key2 := make([]byte, 32)
	rand.Read(key1)
	rand.Read(key2)

	ct := sleepEncrypt(key1, []byte("secret data"))
	if ct == nil {
		t.Fatal("encrypt failed")
	}

	pt := sleepDecrypt(key2, ct)
	if pt != nil {
		t.Error("expected nil on wrong-key decrypt, got data")
	}
}

func TestSleepDecryptCorruptData(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	ct := sleepEncrypt(key, []byte("secret data"))
	if ct == nil {
		t.Fatal("encrypt failed")
	}

	// Flip a byte in the ciphertext
	ct[len(ct)-1] ^= 0xFF

	pt := sleepDecrypt(key, ct)
	if pt != nil {
		t.Error("expected nil on corrupt ciphertext, got data")
	}
}

func TestSleepDecryptTooShort(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	// GCM nonce is 12 bytes; ciphertext shorter than nonce+1 should fail
	pt := sleepDecrypt(key, []byte("short"))
	if pt != nil {
		t.Error("expected nil on too-short ciphertext")
	}
}

func TestSleepEncryptInvalidKey(t *testing.T) {
	// AES requires 16, 24, or 32 byte keys; 15 bytes should fail
	badKey := make([]byte, 15)
	ct := sleepEncrypt(badKey, []byte("test"))
	if ct != nil {
		t.Error("expected nil on invalid key size")
	}
}

func TestSleepEncryptUniqueCiphertexts(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	plaintext := []byte("same input every time")

	ct1 := sleepEncrypt(key, plaintext)
	ct2 := sleepEncrypt(key, plaintext)

	if ct1 == nil || ct2 == nil {
		t.Fatal("encrypt returned nil")
	}
	// Different random nonces should produce different ciphertexts
	if bytes.Equal(ct1, ct2) {
		t.Error("two encryptions of same plaintext should differ (unique nonces)")
	}
}

// --- obfuscateSleep / deobfuscateSleep tests ---

func makeTestAgent() *structs.Agent {
	return &structs.Agent{
		PayloadUUID:   "550e8400-e29b-41d4-a716-446655440000",
		Domain:        "CONTOSO.LOCAL",
		Host:          "WORKSTATION-01",
		User:          "admin",
		InternalIP:    "10.0.0.50",
		ExternalIP:    "203.0.113.10",
		ProcessName:   "svchost.exe",
		Description:   "Fawkes agent 550e8400",
		SleepInterval: 30,
		Jitter:        20,
		PID:           1234,
	}
}

func makeTestHTTPProfile() *fhttp.HTTPProfile {
	return &fhttp.HTTPProfile{
		BaseURL:       "https://c2.example.com:443",
		UserAgent:     "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
		EncryptionKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		CallbackUUID:  "callback-uuid-abc-123",
		HostHeader:    "cdn.example.com",
		GetEndpoint:   "/api/v1/data",
		PostEndpoint:  "/api/v1/submit",
		CustomHeaders: map[string]string{"X-Forwarded-For": "1.2.3.4"},
	}
}

func TestObfuscateSleepZerosAgentFields(t *testing.T) {
	agent := makeTestAgent()
	c2 := profiles.Profile(makeTestHTTPProfile())

	vault := obfuscateSleep(agent, c2)
	if vault == nil {
		t.Fatal("obfuscateSleep returned nil")
	}

	// Agent sensitive fields should be zeroed
	if agent.PayloadUUID != "" {
		t.Error("PayloadUUID not zeroed")
	}
	if agent.Domain != "" {
		t.Error("Domain not zeroed")
	}
	if agent.Host != "" {
		t.Error("Host not zeroed")
	}
	if agent.User != "" {
		t.Error("User not zeroed")
	}
	if agent.InternalIP != "" {
		t.Error("InternalIP not zeroed")
	}
	if agent.ExternalIP != "" {
		t.Error("ExternalIP not zeroed")
	}
	if agent.ProcessName != "" {
		t.Error("ProcessName not zeroed")
	}
	if agent.Description != "" {
		t.Error("Description not zeroed")
	}

	// Non-sensitive fields should be untouched
	if agent.SleepInterval != 30 {
		t.Errorf("SleepInterval changed: got %d", agent.SleepInterval)
	}
	if agent.PID != 1234 {
		t.Errorf("PID changed: got %d", agent.PID)
	}

	// Vault should have encrypted data
	if vault.agentBlob == nil {
		t.Error("vault.agentBlob is nil")
	}
	if vault.key == nil {
		t.Error("vault.key is nil")
	}

	// Clean up
	deobfuscateSleep(vault, agent, c2)
}

func TestObfuscateDeobfuscateRestoresAgentFields(t *testing.T) {
	agent := makeTestAgent()
	origUUID := agent.PayloadUUID
	origDomain := agent.Domain
	origHost := agent.Host
	origUser := agent.User
	origInternalIP := agent.InternalIP
	origExternalIP := agent.ExternalIP
	origProcessName := agent.ProcessName
	origDesc := agent.Description

	c2 := profiles.Profile(makeTestHTTPProfile())

	vault := obfuscateSleep(agent, c2)
	if vault == nil {
		t.Fatal("obfuscateSleep returned nil")
	}

	deobfuscateSleep(vault, agent, c2)

	if agent.PayloadUUID != origUUID {
		t.Errorf("PayloadUUID: got %q, want %q", agent.PayloadUUID, origUUID)
	}
	if agent.Domain != origDomain {
		t.Errorf("Domain: got %q, want %q", agent.Domain, origDomain)
	}
	if agent.Host != origHost {
		t.Errorf("Host: got %q, want %q", agent.Host, origHost)
	}
	if agent.User != origUser {
		t.Errorf("User: got %q, want %q", agent.User, origUser)
	}
	if agent.InternalIP != origInternalIP {
		t.Errorf("InternalIP: got %q, want %q", agent.InternalIP, origInternalIP)
	}
	if agent.ExternalIP != origExternalIP {
		t.Errorf("ExternalIP: got %q, want %q", agent.ExternalIP, origExternalIP)
	}
	if agent.ProcessName != origProcessName {
		t.Errorf("ProcessName: got %q, want %q", agent.ProcessName, origProcessName)
	}
	if agent.Description != origDesc {
		t.Errorf("Description: got %q, want %q", agent.Description, origDesc)
	}
}

func TestObfuscateProfileWhenNoTasksRunning(t *testing.T) {
	agent := makeTestAgent()
	hp := makeTestHTTPProfile()
	c2 := profiles.Profile(hp)

	// Ensure no tasks are running
	// (GetRunningTasks returns empty map by default in tests)

	vault := obfuscateSleep(agent, c2)
	if vault == nil {
		t.Fatal("obfuscateSleep returned nil")
	}

	// Profile should be masked when no tasks are running
	if !vault.profileMasked {
		t.Error("expected profile to be masked when no tasks running")
	}
	if vault.profileBlob == nil {
		t.Error("profileBlob should not be nil when masked")
	}

	// Profile fields should be zeroed
	if hp.EncryptionKey != "" {
		t.Error("EncryptionKey not zeroed")
	}
	if hp.BaseURL != "" {
		t.Error("BaseURL not zeroed")
	}
	if hp.CallbackUUID != "" {
		t.Error("CallbackUUID not zeroed")
	}

	// Restore
	deobfuscateSleep(vault, agent, c2)

	// Profile fields should be restored
	if hp.EncryptionKey != "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" {
		t.Errorf("EncryptionKey not restored: %q", hp.EncryptionKey)
	}
	if hp.BaseURL != "https://c2.example.com:443" {
		t.Errorf("BaseURL not restored: %q", hp.BaseURL)
	}
	if hp.CallbackUUID != "callback-uuid-abc-123" {
		t.Errorf("CallbackUUID not restored: %q", hp.CallbackUUID)
	}
	if hp.CustomHeaders["X-Forwarded-For"] != "1.2.3.4" {
		t.Error("CustomHeaders not restored")
	}
}

func TestObfuscateSkippedEntirelyWhenTasksRunning(t *testing.T) {
	agent := makeTestAgent()
	origUUID := agent.PayloadUUID
	hp := makeTestHTTPProfile()
	c2 := profiles.Profile(hp)

	// Track a fake running task
	task := structs.NewTask("test-task-1", "whoami", "")
	commands.TrackTask(&task)
	defer commands.UntrackTask("test-task-1")

	vault := obfuscateSleep(agent, c2)

	// Should return nil — no masking when tasks are running (data race prevention)
	if vault != nil {
		t.Error("obfuscateSleep should return nil when tasks are running")
	}

	// Agent fields should NOT be modified
	if agent.PayloadUUID != origUUID {
		t.Error("PayloadUUID was incorrectly zeroed while tasks running")
	}

	// Profile fields should NOT be modified
	if hp.EncryptionKey != "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" {
		t.Error("EncryptionKey was incorrectly zeroed while tasks running")
	}
	if hp.BaseURL != "https://c2.example.com:443" {
		t.Error("BaseURL was incorrectly zeroed while tasks running")
	}

	// deobfuscateSleep with nil vault should be a no-op
	deobfuscateSleep(vault, agent, c2)
	if agent.PayloadUUID != origUUID {
		t.Error("deobfuscate with nil vault should be a no-op")
	}
}

func TestDeobfuscateNilVault(t *testing.T) {
	agent := makeTestAgent()
	origUUID := agent.PayloadUUID
	c2 := profiles.Profile(makeTestHTTPProfile())

	// Should be a no-op, not panic
	deobfuscateSleep(nil, agent, c2)

	if agent.PayloadUUID != origUUID {
		t.Error("nil vault deobfuscate should be a no-op")
	}
}

func TestVaultKeyZeroedAfterRestore(t *testing.T) {
	agent := makeTestAgent()
	c2 := profiles.Profile(makeTestHTTPProfile())

	vault := obfuscateSleep(agent, c2)
	if vault == nil {
		t.Fatal("obfuscateSleep returned nil")
	}

	deobfuscateSleep(vault, agent, c2)

	// Key should be nil after deobfuscation
	if vault.key != nil {
		t.Error("vault key should be nil after deobfuscation")
	}
	// Blobs should be nil after deobfuscation
	if vault.agentBlob != nil {
		t.Error("agentBlob should be nil after deobfuscation")
	}
	if vault.profileBlob != nil {
		t.Error("profileBlob should be nil after deobfuscation")
	}
}

func TestMultipleObfuscateCycles(t *testing.T) {
	agent := makeTestAgent()
	origUUID := agent.PayloadUUID
	c2 := profiles.Profile(makeTestHTTPProfile())

	// Run 5 obfuscate/deobfuscate cycles to verify no drift
	for i := 0; i < 5; i++ {
		vault := obfuscateSleep(agent, c2)
		if vault == nil {
			t.Fatalf("cycle %d: obfuscateSleep returned nil", i)
		}
		if agent.PayloadUUID != "" {
			t.Errorf("cycle %d: PayloadUUID not zeroed during sleep", i)
		}
		deobfuscateSleep(vault, agent, c2)
		if agent.PayloadUUID != origUUID {
			t.Errorf("cycle %d: PayloadUUID drift: got %q, want %q", i, agent.PayloadUUID, origUUID)
		}
	}
}
