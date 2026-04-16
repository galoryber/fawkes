//go:build windows
// +build windows

package commands

import (
	"strings"
	"testing"
)

func TestEtwPatch_UnknownTarget(t *testing.T) {
	result := etwPatch("nonexistent")
	if result.Status != "error" {
		t.Errorf("Expected error for unknown target, got %s", result.Status)
	}
	if !strings.Contains(result.Output, "Unknown patch target") {
		t.Errorf("Expected unknown target error, got %q", result.Output)
	}
}

func TestEtwPatch_ValidTargets(t *testing.T) {
	// Verify all target shorthands are accepted (don't actually patch in tests)
	validTargets := []string{"etw", "etwwrite", "etw-register", "etwregister", "all"}
	for _, target := range validTargets {
		keys := resolveTargetKeys(target)
		if len(keys) == 0 {
			t.Errorf("resolveTargetKeys(%q) returned empty", target)
		}
	}
}

func TestResolveTargetKeys_ETW(t *testing.T) {
	keys := resolveTargetKeys("etw")
	if len(keys) != 1 {
		t.Fatalf("Expected 1 key for 'etw', got %d", len(keys))
	}
	if !strings.Contains(keys[0], "ntdll.dll!") {
		t.Errorf("Expected ntdll.dll prefix, got %q", keys[0])
	}
}

func TestResolveTargetKeys_Register(t *testing.T) {
	keys := resolveTargetKeys("etw-register")
	if len(keys) != 1 {
		t.Fatalf("Expected 1 key for 'etw-register', got %d", len(keys))
	}
	if keys[0] != "ntdll.dll!EtwEventRegister" {
		t.Errorf("Expected ntdll.dll!EtwEventRegister, got %q", keys[0])
	}
}

func TestResolveTargetKeys_Custom(t *testing.T) {
	keys := resolveTargetKeys("custom.dll!CustomFunc")
	if len(keys) != 1 || keys[0] != "custom.dll!CustomFunc" {
		t.Errorf("Custom target should pass through, got %v", keys)
	}
}

func TestEtwRestore_NothingToRestore(t *testing.T) {
	// Clear any existing patches
	etwPatchMu.Lock()
	origStore := etwPatchStore
	etwPatchStore = make(map[string][]byte)
	etwPatchMu.Unlock()
	defer func() {
		etwPatchMu.Lock()
		etwPatchStore = origStore
		etwPatchMu.Unlock()
	}()

	result := etwRestore("")
	if result.Status != "success" {
		t.Errorf("Expected success for empty store, got %s", result.Status)
	}
	if !strings.Contains(result.Output, "No active patches") {
		t.Errorf("Expected no-patch message, got %q", result.Output)
	}
}

func TestEtwPatchStore_AlreadyPatched(t *testing.T) {
	// Simulate a patched entry
	etwPatchMu.Lock()
	origStore := etwPatchStore
	etwPatchStore = make(map[string][]byte)
	etwPatchStore["ntdll.dll!TestFunc"] = []byte{0x48}
	etwPatchMu.Unlock()
	defer func() {
		etwPatchMu.Lock()
		etwPatchStore = origStore
		etwPatchMu.Unlock()
	}()

	// Verify the store has the entry
	etwPatchMu.Lock()
	_, exists := etwPatchStore["ntdll.dll!TestFunc"]
	etwPatchMu.Unlock()
	if !exists {
		t.Error("Expected patched entry in store")
	}
}
