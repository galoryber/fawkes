//go:build windows

package commands

import (
	"encoding/json"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestGetSystemCommand_NameAndDescription(t *testing.T) {
	cmd := &GetSystemCommand{}
	if cmd.Name() != "getsystem" {
		t.Errorf("Name() = %q, want %q", cmd.Name(), "getsystem")
	}
	if cmd.Description() == "" {
		t.Error("Description() should not be empty")
	}
	if !strings.Contains(cmd.Description(), "SYSTEM") {
		t.Error("Description should mention SYSTEM")
	}
	if !strings.Contains(cmd.Description(), "SeImpersonate") {
		t.Error("Description should mention SeImpersonate")
	}
}

func TestGetSystemCommand_InvalidJSON(t *testing.T) {
	cmd := &GetSystemCommand{}
	result := cmd.Execute(structs.Task{Params: "not json"})
	if result.Status != "error" {
		t.Errorf("expected error for invalid JSON, got %q", result.Status)
	}
	if !result.Completed {
		t.Error("expected Completed=true")
	}
}

func TestGetSystemCommand_UnknownTechnique(t *testing.T) {
	cmd := &GetSystemCommand{}
	params, _ := json.Marshal(getSystemArgs{Technique: "badtechnique"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error for unknown technique, got %q", result.Status)
	}
	if !strings.Contains(result.Output, "Unknown technique") {
		t.Errorf("expected 'Unknown technique' in output, got: %s", result.Output)
	}
}

func TestGetSystemCommand_DefaultTechnique(t *testing.T) {
	// Empty params should default to "service" technique
	// This will fail because we're not admin, but it should attempt
	// the service technique (not return "unknown technique")
	cmd := &GetSystemCommand{}
	result := cmd.Execute(structs.Task{Params: ""})
	// Should attempt service technique and fail on SCM connect (not admin)
	// or succeed if running as admin
	if result.Status == "error" {
		if strings.Contains(result.Output, "Unknown technique") {
			t.Error("empty params should default to service technique")
		}
	}
}

func TestGetSystemCommand_ServiceTechniqueExplicit(t *testing.T) {
	cmd := &GetSystemCommand{}
	params, _ := json.Marshal(getSystemArgs{Technique: "service"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	// Should attempt service technique and fail on SCM connect (not admin)
	// or succeed if running as admin
	if result.Status == "error" {
		if strings.Contains(result.Output, "Unknown technique") {
			t.Error("'service' should be a recognized technique")
		}
	}
}

func TestRandomPipeName(t *testing.T) {
	name1, err := randomPipeName()
	if err != nil {
		t.Fatalf("randomPipeName() failed: %v", err)
	}
	if len(name1) != 16 { // 8 bytes = 16 hex chars
		t.Errorf("expected 16 hex chars, got %d: %s", len(name1), name1)
	}

	// Verify randomness — two calls should produce different names
	name2, err := randomPipeName()
	if err != nil {
		t.Fatalf("randomPipeName() second call failed: %v", err)
	}
	if name1 == name2 {
		t.Errorf("two calls to randomPipeName returned same value: %s", name1)
	}

	// Verify it's valid hex
	for _, c := range name1 {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Errorf("unexpected character in pipe name: %c", c)
		}
	}
}

func TestGetSystemArgs_JSONParsing(t *testing.T) {
	// Test that the args struct parses correctly
	input := `{"technique":"service"}`
	var args getSystemArgs
	err := json.Unmarshal([]byte(input), &args)
	if err != nil {
		t.Fatalf("failed to parse JSON: %v", err)
	}
	if args.Technique != "service" {
		t.Errorf("Technique = %q, want %q", args.Technique, "service")
	}

	// Test empty JSON
	input = `{}`
	err = json.Unmarshal([]byte(input), &args)
	if err != nil {
		t.Fatalf("failed to parse empty JSON: %v", err)
	}
	if args.Technique != "" {
		t.Errorf("Technique should be empty for {}, got %q", args.Technique)
	}
}
