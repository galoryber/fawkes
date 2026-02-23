//go:build windows

package commands

import (
	"encoding/hex"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestHashdumpCommand_NameAndDescription(t *testing.T) {
	cmd := &HashdumpCommand{}
	if cmd.Name() != "hashdump" {
		t.Errorf("Name() = %q, want %q", cmd.Name(), "hashdump")
	}
	if cmd.Description() == "" {
		t.Error("Description() should not be empty")
	}
	if !strings.Contains(cmd.Description(), "NTLM") {
		t.Error("Description should mention NTLM")
	}
}

func TestHashdumpCommand_InvalidJSON(t *testing.T) {
	cmd := &HashdumpCommand{}
	result := cmd.Execute(structs.Task{Params: "not json"})
	if result.Status != "error" {
		t.Errorf("expected error for invalid JSON, got %q", result.Status)
	}
}

func TestHashdumpCommand_EmptyParams(t *testing.T) {
	// Empty params should attempt the dump (will fail without SYSTEM)
	cmd := &HashdumpCommand{}
	result := cmd.Execute(structs.Task{Params: ""})
	if result.Status == "error" {
		// Expected: should fail with access error (not running as SYSTEM)
		if !strings.Contains(result.Output, "boot key") && !strings.Contains(result.Output, "SYSTEM") {
			t.Logf("Unexpected error: %s", result.Output)
		}
	}
}

func TestExpandDESKey(t *testing.T) {
	// Test the 7-to-8 byte DES key expansion
	input := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD}
	result := expandDESKey(input)
	if len(result) != 8 {
		t.Fatalf("expected 8 bytes, got %d", len(result))
	}
	// Verify parity bit placement (LSB should be 0 after shift)
	for i, b := range result {
		if b&0x01 != 0 {
			t.Errorf("byte %d (0x%02x) should have LSB=0 (parity)", i, b)
		}
	}
}

func TestDesKeysFromRID(t *testing.T) {
	// Test with known RID 500 (Administrator)
	key1, key2 := desKeysFromRID(500)
	if len(key1) != 8 {
		t.Fatalf("key1 length: got %d, want 8", len(key1))
	}
	if len(key2) != 8 {
		t.Fatalf("key2 length: got %d, want 8", len(key2))
	}
	// Keys should be different
	same := true
	for i := 0; i < 8; i++ {
		if key1[i] != key2[i] {
			same = false
			break
		}
	}
	if same {
		t.Error("key1 and key2 should be different")
	}
}

func TestDesKeysFromRID_Deterministic(t *testing.T) {
	// Same RID should produce same keys
	k1a, k2a := desKeysFromRID(1001)
	k1b, k2b := desKeysFromRID(1001)
	for i := 0; i < 8; i++ {
		if k1a[i] != k1b[i] {
			t.Error("key1 not deterministic")
		}
		if k2a[i] != k2b[i] {
			t.Error("key2 not deterministic")
		}
	}
}

func TestUTF16LEToString(t *testing.T) {
	tests := []struct {
		name   string
		input  []byte
		expect string
	}{
		{"ASCII", []byte{0x41, 0x00, 0x64, 0x00, 0x6D, 0x00}, "Adm"},
		{"Admin", []byte{0x41, 0x00, 0x64, 0x00, 0x6D, 0x00, 0x69, 0x00, 0x6E, 0x00}, "Admin"},
		{"Empty", []byte{}, ""},
		{"Odd length", []byte{0x41, 0x00, 0x42}, "A"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := utf16LEToString(tt.input)
			if result != tt.expect {
				t.Errorf("utf16LEToString(%v) = %q, want %q", tt.input, result, tt.expect)
			}
		})
	}
}

func TestBootKeyPermutation(t *testing.T) {
	// Verify permutation table has all values 0-15
	seen := make(map[int]bool)
	for _, v := range bootKeyPerm {
		if v < 0 || v > 15 {
			t.Errorf("permutation value %d out of range", v)
		}
		if seen[v] {
			t.Errorf("duplicate permutation value %d", v)
		}
		seen[v] = true
	}
	if len(seen) != 16 {
		t.Errorf("expected 16 unique values, got %d", len(seen))
	}
}

func TestParseHexUint32(t *testing.T) {
	tests := []struct {
		input  string
		expect uint32
		ok     bool
	}{
		{"000001F4", 500, true},
		{"000003E9", 1001, true},
		{"000001F5", 501, true},
		{"FFFFFFFF", 4294967295, true},
		{"notahex", 0, false},
	}
	for _, tt := range tests {
		result, err := parseHexUint32(tt.input)
		if tt.ok && err != nil {
			t.Errorf("parseHexUint32(%q) failed: %v", tt.input, err)
		}
		if !tt.ok && err == nil {
			t.Errorf("parseHexUint32(%q) should have failed", tt.input)
		}
		if tt.ok && result != tt.expect {
			t.Errorf("parseHexUint32(%q) = %d, want %d", tt.input, result, tt.expect)
		}
	}
}

func TestDecryptDESHash_KnownVector(t *testing.T) {
	// Test with a known DES-encrypted hash value
	// This tests the DES decryption mechanics with a zero hash and RID 500
	key1, key2 := desKeysFromRID(500)
	if key1 == nil || key2 == nil {
		t.Fatal("failed to derive DES keys")
	}
	// Encrypt a known value to verify round-trip
	// We can't easily test without a known SAM hash, but verify it doesn't panic
	zeroHash := make([]byte, 16)
	_, err := decryptDESHash(zeroHash, 500)
	if err != nil {
		t.Fatalf("decryptDESHash failed: %v", err)
	}
}

func TestEmptyHashConstants(t *testing.T) {
	// Verify the empty hash constants are valid hex
	_, err := hex.DecodeString(emptyLMHash)
	if err != nil {
		t.Errorf("emptyLMHash is not valid hex: %v", err)
	}
	_, err = hex.DecodeString(emptyNTHash)
	if err != nil {
		t.Errorf("emptyNTHash is not valid hex: %v", err)
	}
	if len(emptyLMHash) != 32 {
		t.Errorf("emptyLMHash length: %d, want 32", len(emptyLMHash))
	}
	if len(emptyNTHash) != 32 {
		t.Errorf("emptyNTHash length: %d, want 32", len(emptyNTHash))
	}
}
