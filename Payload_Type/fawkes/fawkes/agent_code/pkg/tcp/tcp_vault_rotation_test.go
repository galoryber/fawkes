package tcp

import (
	"bytes"
	"testing"
)

func TestTCPRotateVaultKey_PreservesConfig(t *testing.T) {
	p := NewTCPProfile("0.0.0.0:9999", "dGVzdGtleQ==", false)
	p.CallbackUUID = "tcp-uuid-1234"

	if err := p.SealConfig(); err != nil {
		t.Fatalf("SealConfig failed: %v", err)
	}

	if err := p.RotateVaultKey(); err != nil {
		t.Fatalf("RotateVaultKey failed: %v", err)
	}

	cfg := p.getConfig()
	if cfg == nil {
		t.Fatal("getConfig returned nil after rotation")
	}
	if cfg.EncryptionKey != "dGVzdGtleQ==" {
		t.Errorf("EncryptionKey = %q after rotation", cfg.EncryptionKey)
	}
	if cfg.CallbackUUID != "tcp-uuid-1234" {
		t.Errorf("CallbackUUID = %q after rotation", cfg.CallbackUUID)
	}
}

func TestTCPRotateVaultKey_ChangesKey(t *testing.T) {
	p := NewTCPProfile("0.0.0.0:9999", "dGVzdGtleQ==", false)
	if err := p.SealConfig(); err != nil {
		t.Fatalf("SealConfig failed: %v", err)
	}

	oldKey := make([]byte, len(p.vault.key))
	copy(oldKey, p.vault.key)

	if err := p.RotateVaultKey(); err != nil {
		t.Fatalf("RotateVaultKey failed: %v", err)
	}

	if bytes.Equal(p.vault.key, oldKey) {
		t.Error("vault key did not change after rotation")
	}
}

func TestTCPRotateVaultKey_ZerosOldKey(t *testing.T) {
	p := NewTCPProfile("0.0.0.0:9999", "dGVzdGtleQ==", false)
	if err := p.SealConfig(); err != nil {
		t.Fatalf("SealConfig failed: %v", err)
	}

	oldKey := p.vault.key
	if err := p.RotateVaultKey(); err != nil {
		t.Fatalf("RotateVaultKey failed: %v", err)
	}

	for i, b := range oldKey {
		if b != 0 {
			t.Errorf("old key byte %d not zeroed: got 0x%02x", i, b)
			break
		}
	}
}

func TestTCPRotateVaultKey_UnsealedNoop(t *testing.T) {
	p := NewTCPProfile("0.0.0.0:9999", "dGVzdGtleQ==", false)
	if err := p.RotateVaultKey(); err != nil {
		t.Errorf("RotateVaultKey on unsealed vault should return nil, got: %v", err)
	}
}

func TestTCPRotateVaultKey_MultipleRotations(t *testing.T) {
	p := NewTCPProfile("0.0.0.0:9999", "dGVzdGtleQ==", false)
	p.CallbackUUID = "uuid-multi"

	if err := p.SealConfig(); err != nil {
		t.Fatalf("SealConfig failed: %v", err)
	}

	for i := 0; i < 10; i++ {
		if err := p.RotateVaultKey(); err != nil {
			t.Fatalf("rotation %d failed: %v", i, err)
		}
	}

	cfg := p.getConfig()
	if cfg == nil {
		t.Fatal("getConfig returned nil after 10 rotations")
	}
	if cfg.EncryptionKey != "dGVzdGtleQ==" {
		t.Errorf("EncryptionKey = %q after 10 rotations", cfg.EncryptionKey)
	}
	if cfg.CallbackUUID != "uuid-multi" {
		t.Errorf("CallbackUUID = %q after 10 rotations", cfg.CallbackUUID)
	}
}
