//go:build windows
// +build windows

package commands

import (
	"encoding/json"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestUACBypassNameAndDescription(t *testing.T) {
	cmd := &UACBypassCommand{}
	if cmd.Name() != "uac-bypass" {
		t.Errorf("Expected name 'uac-bypass', got '%s'", cmd.Name())
	}
	if cmd.Description() == "" {
		t.Error("Description should not be empty")
	}
}

func TestUACBypassInvalidJSON(t *testing.T) {
	cmd := &UACBypassCommand{}
	task := structs.Task{Params: "not json"}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Error("Expected error status for invalid JSON")
	}
	if !strings.Contains(result.Output, "Error parsing parameters") {
		t.Errorf("Expected parsing error, got: %s", result.Output)
	}
}

func TestUACBypassUnknownTechnique(t *testing.T) {
	cmd := &UACBypassCommand{}
	params, _ := json.Marshal(map[string]string{
		"technique": "nonexistent",
		"command":   "notepad.exe",
	})
	task := structs.Task{Params: string(params)}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Error("Expected error status for unknown technique")
	}
	if !strings.Contains(result.Output, "Unknown technique") {
		t.Errorf("Expected unknown technique error, got: %s", result.Output)
	}
}

func TestUACBypassDefaultTechnique(t *testing.T) {
	cmd := &UACBypassCommand{}
	// Empty technique should default to fodhelper
	params, _ := json.Marshal(map[string]string{
		"command": "notepad.exe",
	})
	task := structs.Task{Params: string(params)}
	result := cmd.Execute(task)
	// Will either succeed (if medium integrity) or say already elevated (if high integrity)
	// Either way, should not be an "error parsing" or "unknown technique" error
	if strings.Contains(result.Output, "Unknown technique") {
		t.Error("Default technique should be valid")
	}
}

func TestUACBypassIsElevatedCheck(t *testing.T) {
	// Test the isElevated function directly
	// Should return a boolean without crashing
	elevated := isElevated()
	_ = elevated // Just verify it doesn't panic
}

func TestUACBypassAlreadyElevated(t *testing.T) {
	// If running tests as admin, should detect elevation
	if !isElevated() {
		t.Skip("Test only runs when already elevated")
	}
	cmd := &UACBypassCommand{}
	params, _ := json.Marshal(map[string]string{
		"technique": "fodhelper",
	})
	task := structs.Task{Params: string(params)}
	result := cmd.Execute(task)
	if !strings.Contains(result.Output, "Already running at high integrity") {
		t.Errorf("Expected elevation detection, got: %s", result.Output)
	}
}

func TestUACBypassEmptyParams(t *testing.T) {
	cmd := &UACBypassCommand{}
	task := structs.Task{Params: ""}
	result := cmd.Execute(task)
	// Should not error on empty params (uses defaults)
	if strings.Contains(result.Output, "Error parsing parameters") {
		t.Error("Should handle empty params gracefully")
	}
}

func TestUACBypassCleanupMsSettingsKey(t *testing.T) {
	// Test that cleanup doesn't panic even when keys don't exist
	cleanupMsSettingsKey()
}

func TestUACBypassCleanupSdcltKey(t *testing.T) {
	// Test that cleanup doesn't panic even when keys don't exist
	cleanupSdcltKey()
}

func TestUACBypassTechniqueNormalization(t *testing.T) {
	cmd := &UACBypassCommand{}
	// Test uppercase technique name (should be normalized to lowercase)
	params, _ := json.Marshal(map[string]string{
		"technique": "FODHELPER",
		"command":   "notepad.exe",
	})
	task := structs.Task{Params: string(params)}
	result := cmd.Execute(task)
	// Should not fail with "Unknown technique" — case normalization should work
	if strings.Contains(result.Output, "Unknown technique") {
		t.Error("Technique should be case-insensitive")
	}
}

func TestUACBypassAllTechniqueNames(t *testing.T) {
	// Verify all documented techniques are recognized (don't trigger "Unknown technique")
	techniques := []string{"fodhelper", "computerdefaults", "sdclt", "eventvwr", "silentcleanup", "cmstp"}
	cmd := &UACBypassCommand{}

	for _, tech := range techniques {
		params, _ := json.Marshal(map[string]string{
			"technique": tech,
			"command":   "notepad.exe",
		})
		task := structs.Task{Params: string(params)}
		result := cmd.Execute(task)
		if strings.Contains(result.Output, "Unknown technique") {
			t.Errorf("Technique '%s' should be recognized but got: %s", tech, result.Output)
		}
	}
}

// --- T4 OPSEC tests: dynamic paths + registry shredding ---

func TestResolveSystem32Binary(t *testing.T) {
	path := resolveSystem32Binary("sdclt.exe")
	if path == "" {
		t.Error("resolveSystem32Binary returned empty string")
	}
	if !strings.HasSuffix(path, `sdclt.exe`) {
		t.Errorf("path should end with sdclt.exe: %s", path)
	}
	if !strings.Contains(strings.ToLower(path), `system32`) {
		t.Errorf("path should contain System32: %s", path)
	}
}

func TestResolveSystem32Binary_Various(t *testing.T) {
	binaries := []string{"fodhelper.exe", "computerdefaults.exe", "sdclt.exe", "cmd.exe"}
	for _, bin := range binaries {
		path := resolveSystem32Binary(bin)
		if !strings.HasSuffix(path, bin) {
			t.Errorf("resolveSystem32Binary(%q) = %q, should end with %q", bin, path, bin)
		}
	}
}

func TestResolveSystem32Binary_NeverHardcoded(t *testing.T) {
	// If WINDIR is set (should be on Windows), path should use it
	path := resolveSystem32Binary("test.exe")
	// Should not be the literal hardcoded fallback if env vars are available
	if path == `C:\Windows\System32\test.exe` {
		// This is the fallback — only acceptable if both WINDIR and SystemRoot are empty
		t.Log("Using fallback path — WINDIR and SystemRoot env vars may not be set")
	}
}

func TestRandomShredString(t *testing.T) {
	s := randomShredString()
	if len(s) != 64 {
		t.Errorf("expected 64 chars, got %d", len(s))
	}
	// Should be all alphanumeric
	for _, c := range s {
		if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) {
			t.Errorf("unexpected character in shred string: %c", c)
		}
	}
}

func TestRandomShredString_Unique(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 20; i++ {
		s := randomShredString()
		if seen[s] {
			t.Errorf("duplicate shred string on iteration %d", i)
		}
		seen[s] = true
	}
}

func TestUACBypassCleanupEventvwrKey(t *testing.T) {
	// Test that cleanup doesn't panic even when keys don't exist
	cleanupEventvwrKey()
}

func TestUACBypassEventvwrTechniqueRecognized(t *testing.T) {
	cmd := &UACBypassCommand{}
	params, _ := json.Marshal(map[string]string{
		"technique": "eventvwr",
		"command":   "notepad.exe",
	})
	task := structs.Task{Params: string(params)}
	result := cmd.Execute(task)
	if strings.Contains(result.Output, "Unknown technique") {
		t.Error("eventvwr technique should be recognized")
	}
	// Should mention the technique name in output
	if !strings.Contains(result.Output, "eventvwr") {
		t.Error("Output should mention eventvwr technique")
	}
}

func TestUACBypassSilentCleanupTechniqueRecognized(t *testing.T) {
	cmd := &UACBypassCommand{}
	params, _ := json.Marshal(map[string]string{
		"technique": "silentcleanup",
		"command":   "notepad.exe",
	})
	task := structs.Task{Params: string(params)}
	result := cmd.Execute(task)
	if strings.Contains(result.Output, "Unknown technique") {
		t.Error("silentcleanup technique should be recognized")
	}
	if !strings.Contains(result.Output, "silentcleanup") {
		t.Error("Output should mention silentcleanup technique")
	}
}

func TestUACBypassCmstpTechniqueRecognized(t *testing.T) {
	cmd := &UACBypassCommand{}
	params, _ := json.Marshal(map[string]string{
		"technique": "cmstp",
		"command":   "notepad.exe",
	})
	task := structs.Task{Params: string(params)}
	result := cmd.Execute(task)
	if strings.Contains(result.Output, "Unknown technique") {
		t.Error("cmstp technique should be recognized")
	}
	if !strings.Contains(result.Output, "cmstp") {
		t.Error("Output should mention cmstp technique")
	}
}

func TestUACBypassNewTechniquesCaseInsensitive(t *testing.T) {
	cmd := &UACBypassCommand{}
	techniques := []string{"EVENTVWR", "SilentCleanup", "CMSTP", "Eventvwr"}
	for _, tech := range techniques {
		params, _ := json.Marshal(map[string]string{
			"technique": tech,
			"command":   "notepad.exe",
		})
		task := structs.Task{Params: string(params)}
		result := cmd.Execute(task)
		if strings.Contains(result.Output, "Unknown technique") {
			t.Errorf("Technique '%s' should be case-insensitive but got: %s", tech, result.Output)
		}
	}
}
