//go:build windows

package main

import (
	"bytes"
	"testing"
)

func TestGuardSleepPagesNilVault(t *testing.T) {
	guard := guardSleepPages(nil)
	if guard != nil {
		t.Fatal("expected nil guard for nil vault")
	}
}

func TestGuardSleepPagesNilKey(t *testing.T) {
	vault := &sleepVault{}
	guard := guardSleepPages(vault)
	if guard != nil {
		t.Fatal("expected nil guard for vault with nil key")
	}
}

func TestGuardSleepPagesRoundTrip(t *testing.T) {
	// Set up vault with test data
	vault := &sleepVault{
		key:           []byte("0123456789abcdef0123456789abcdef"), // 32 bytes
		agentBlob:     []byte("encrypted-agent-data-here"),
		profileBlob:   []byte("encrypted-profile-data"),
		profileMasked: true,
		tcpBlob:       []byte("encrypted-tcp"),
		tcpMasked:     true,
	}

	origKey := make([]byte, len(vault.key))
	origAgent := make([]byte, len(vault.agentBlob))
	origProfile := make([]byte, len(vault.profileBlob))
	origTcp := make([]byte, len(vault.tcpBlob))
	copy(origKey, vault.key)
	copy(origAgent, vault.agentBlob)
	copy(origProfile, vault.profileBlob)
	copy(origTcp, vault.tcpBlob)

	// Guard: moves data to VirtualAlloc'd pages, zeros Go heap
	guard := guardSleepPages(vault)
	if guard == nil {
		t.Fatal("guardSleepPages returned nil")
	}

	// Verify Go heap copies were zeroed
	if vault.key != nil {
		t.Error("vault.key should be nil after guard")
	}
	if vault.agentBlob != nil {
		t.Error("vault.agentBlob should be nil after guard")
	}
	if vault.profileBlob != nil {
		t.Error("vault.profileBlob should be nil after guard")
	}
	if vault.tcpBlob != nil {
		t.Error("vault.tcpBlob should be nil after guard")
	}

	// Unguard: restores data from VirtualAlloc'd pages
	unguardSleepPages(guard, vault)

	// Verify data was restored correctly
	if !bytes.Equal(vault.key, origKey) {
		t.Errorf("key mismatch: got %x, want %x", vault.key, origKey)
	}
	if !bytes.Equal(vault.agentBlob, origAgent) {
		t.Errorf("agentBlob mismatch: got %x, want %x", vault.agentBlob, origAgent)
	}
	if !bytes.Equal(vault.profileBlob, origProfile) {
		t.Errorf("profileBlob mismatch: got %x, want %x", vault.profileBlob, origProfile)
	}
	if !bytes.Equal(vault.tcpBlob, origTcp) {
		t.Errorf("tcpBlob mismatch: got %x, want %x", vault.tcpBlob, origTcp)
	}
}

func TestGuardSleepPagesKeyOnly(t *testing.T) {
	// Vault with only key (no blobs — e.g., obfuscateSleep failed after key gen)
	vault := &sleepVault{
		key: []byte("0123456789abcdef0123456789abcdef"),
	}
	origKey := make([]byte, len(vault.key))
	copy(origKey, vault.key)

	guard := guardSleepPages(vault)
	if guard == nil {
		t.Fatal("guardSleepPages returned nil for key-only vault")
	}

	unguardSleepPages(guard, vault)

	if !bytes.Equal(vault.key, origKey) {
		t.Errorf("key mismatch: got %x, want %x", vault.key, origKey)
	}
	if vault.agentBlob != nil {
		t.Error("agentBlob should still be nil")
	}
}

func TestUnguardNilGuard(t *testing.T) {
	vault := &sleepVault{}
	// Should not panic
	unguardSleepPages(nil, vault)
	unguardSleepPages(nil, nil)
}

func TestGuardSleepPagesMultipleCycles(t *testing.T) {
	for i := 0; i < 5; i++ {
		vault := &sleepVault{
			key:       []byte("0123456789abcdef0123456789abcdef"),
			agentBlob: []byte("cycle-test-data"),
		}
		origKey := make([]byte, len(vault.key))
		origAgent := make([]byte, len(vault.agentBlob))
		copy(origKey, vault.key)
		copy(origAgent, vault.agentBlob)

		guard := guardSleepPages(vault)
		if guard == nil {
			t.Fatalf("cycle %d: guardSleepPages returned nil", i)
		}
		unguardSleepPages(guard, vault)

		if !bytes.Equal(vault.key, origKey) {
			t.Fatalf("cycle %d: key mismatch", i)
		}
		if !bytes.Equal(vault.agentBlob, origAgent) {
			t.Fatalf("cycle %d: agentBlob mismatch", i)
		}
	}
}
