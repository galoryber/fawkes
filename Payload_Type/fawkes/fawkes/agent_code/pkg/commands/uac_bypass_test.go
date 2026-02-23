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
	techniques := []string{"fodhelper", "computerdefaults", "sdclt"}
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
