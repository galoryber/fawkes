package commands

import (
	"testing"
)

func TestSmbDecodeHash_ValidNTHash(t *testing.T) {
	// Pure NT hash (32 hex chars = 16 bytes)
	hash, err := smbDecodeHash("8846f7eaee8fb117ad06bdd830b7586c")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(hash) != 16 {
		t.Errorf("expected 16 bytes, got %d", len(hash))
	}
}

func TestSmbDecodeHash_LMNTFormat(t *testing.T) {
	// LM:NT format — should strip the LM portion
	hash, err := smbDecodeHash("aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(hash) != 16 {
		t.Errorf("expected 16 bytes, got %d", len(hash))
	}
}

func TestSmbDecodeHash_InvalidHex(t *testing.T) {
	_, err := smbDecodeHash("not-valid-hex-string-at-all!!!")
	if err == nil {
		t.Error("expected error for invalid hex")
	}
}

func TestSmbDecodeHash_WrongLength(t *testing.T) {
	// Valid hex but wrong length (8 bytes instead of 16)
	_, err := smbDecodeHash("aabbccdd11223344")
	if err == nil {
		t.Error("expected error for wrong-length hash")
	}
}

func TestSmbDecodeHash_EmptyString(t *testing.T) {
	_, err := smbDecodeHash("")
	if err == nil {
		t.Error("expected error for empty string")
	}
}

func TestSmbDecodeHash_Whitespace(t *testing.T) {
	// stripLMPrefix trims whitespace
	hash, err := smbDecodeHash("  8846f7eaee8fb117ad06bdd830b7586c  ")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(hash) != 16 {
		t.Errorf("expected 16 bytes, got %d", len(hash))
	}
}

func TestSmbDecodeHash_UppercaseHex(t *testing.T) {
	hash, err := smbDecodeHash("8846F7EAEE8FB117AD06BDD830B7586C")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(hash) != 16 {
		t.Errorf("expected 16 bytes, got %d", len(hash))
	}
}
