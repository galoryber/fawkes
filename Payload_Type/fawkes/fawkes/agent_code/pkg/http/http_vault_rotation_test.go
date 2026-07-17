package http

import (
	"bytes"
	"sync"
	"testing"
)

func TestRotateVaultKey_PreservesConfig(t *testing.T) {
	profile := &HTTPProfile{
		BaseURL:       "http://c2.example.com:443",
		UserAgent:     "Mozilla/5.0 Test",
		EncryptionKey: "dGVzdGtleWJhc2U2NA==",
		CallbackUUID:  "test-uuid-1234",
		HostHeader:    "cdn.example.com",
		GetEndpoint:   "/api/get",
		PostEndpoint:  "/api/post",
	}

	if err := profile.SealConfig(); err != nil {
		t.Fatalf("SealConfig failed: %v", err)
	}

	if err := profile.RotateVaultKey(); err != nil {
		t.Fatalf("RotateVaultKey failed: %v", err)
	}

	cfg := profile.getConfig()
	if cfg == nil {
		t.Fatal("getConfig returned nil after rotation")
	}
	if cfg.BaseURL != "http://c2.example.com:443" {
		t.Errorf("BaseURL = %q after rotation", cfg.BaseURL)
	}
	if cfg.UserAgent != "Mozilla/5.0 Test" {
		t.Errorf("UserAgent = %q after rotation", cfg.UserAgent)
	}
	if cfg.EncryptionKey != "dGVzdGtleWJhc2U2NA==" {
		t.Errorf("EncryptionKey = %q after rotation", cfg.EncryptionKey)
	}
	if cfg.CallbackUUID != "test-uuid-1234" {
		t.Errorf("CallbackUUID = %q after rotation", cfg.CallbackUUID)
	}
}

func TestRotateVaultKey_ChangesKey(t *testing.T) {
	profile := &HTTPProfile{
		BaseURL:       "http://c2.example.com",
		EncryptionKey: "key123",
	}

	if err := profile.SealConfig(); err != nil {
		t.Fatalf("SealConfig failed: %v", err)
	}

	oldKey := make([]byte, len(profile.vault.key))
	copy(oldKey, profile.vault.key)

	if err := profile.RotateVaultKey(); err != nil {
		t.Fatalf("RotateVaultKey failed: %v", err)
	}

	if bytes.Equal(profile.vault.key, oldKey) {
		t.Error("vault key did not change after rotation")
	}
}

func TestRotateVaultKey_ZerosOldKey(t *testing.T) {
	profile := &HTTPProfile{
		BaseURL:       "http://c2.example.com",
		EncryptionKey: "key123",
	}

	if err := profile.SealConfig(); err != nil {
		t.Fatalf("SealConfig failed: %v", err)
	}

	oldKey := profile.vault.key

	if err := profile.RotateVaultKey(); err != nil {
		t.Fatalf("RotateVaultKey failed: %v", err)
	}

	for i, b := range oldKey {
		if b != 0 {
			t.Errorf("old key byte %d not zeroed: got 0x%02x", i, b)
			break
		}
	}
}

func TestRotateVaultKey_ZerosOldBlob(t *testing.T) {
	profile := &HTTPProfile{
		BaseURL:       "http://c2.example.com",
		EncryptionKey: "key123",
	}

	if err := profile.SealConfig(); err != nil {
		t.Fatalf("SealConfig failed: %v", err)
	}

	oldBlob := profile.vault.blob

	if err := profile.RotateVaultKey(); err != nil {
		t.Fatalf("RotateVaultKey failed: %v", err)
	}

	for i, b := range oldBlob {
		if b != 0 {
			t.Errorf("old blob byte %d not zeroed: got 0x%02x", i, b)
			break
		}
	}
}

func TestRotateVaultKey_UnsealedNoop(t *testing.T) {
	profile := &HTTPProfile{
		BaseURL: "http://c2.example.com",
	}

	err := profile.RotateVaultKey()
	if err != nil {
		t.Errorf("RotateVaultKey on unsealed vault should return nil, got: %v", err)
	}
}

func TestRotateVaultKey_MultipleRotations(t *testing.T) {
	profile := &HTTPProfile{
		BaseURL:       "http://c2.example.com:443",
		UserAgent:     "Mozilla/5.0",
		EncryptionKey: "multiRotationKey",
		CallbackUUID:  "uuid-multi",
	}

	if err := profile.SealConfig(); err != nil {
		t.Fatalf("SealConfig failed: %v", err)
	}

	for i := 0; i < 10; i++ {
		if err := profile.RotateVaultKey(); err != nil {
			t.Fatalf("rotation %d failed: %v", i, err)
		}
	}

	cfg := profile.getConfig()
	if cfg == nil {
		t.Fatal("getConfig returned nil after 10 rotations")
	}
	if cfg.BaseURL != "http://c2.example.com:443" {
		t.Errorf("BaseURL = %q after 10 rotations", cfg.BaseURL)
	}
	if cfg.EncryptionKey != "multiRotationKey" {
		t.Errorf("EncryptionKey = %q after 10 rotations", cfg.EncryptionKey)
	}
}

func TestRotateVaultKey_ConcurrentAccess(t *testing.T) {
	profile := &HTTPProfile{
		BaseURL:       "http://c2.example.com",
		EncryptionKey: "concurrentKey",
		CallbackUUID:  "uuid-concurrent",
	}

	if err := profile.SealConfig(); err != nil {
		t.Fatalf("SealConfig failed: %v", err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cfg := profile.getConfig()
			if cfg == nil {
				t.Error("getConfig returned nil during concurrent access")
			}
		}()
	}
	wg.Wait()
}
