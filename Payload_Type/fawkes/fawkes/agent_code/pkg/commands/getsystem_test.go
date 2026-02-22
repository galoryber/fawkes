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
	// Empty params should default to "steal" technique
	cmd := &GetSystemCommand{}
	result := cmd.Execute(structs.Task{Params: ""})
	// Should attempt steal technique — might fail on non-admin but shouldn't error as "unknown"
	if result.Status == "error" {
		if strings.Contains(result.Output, "Unknown technique") {
			t.Error("empty params should default to steal technique")
		}
	}
}

func TestGetSystemCommand_StealTechniqueExplicit(t *testing.T) {
	cmd := &GetSystemCommand{}
	params, _ := json.Marshal(getSystemArgs{Technique: "steal"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	// Should attempt steal technique — might fail on non-admin
	if result.Status == "error" {
		if strings.Contains(result.Output, "Unknown technique") {
			t.Error("'steal' should be a recognized technique")
		}
	}
}

func TestGetSystemArgs_JSONParsing(t *testing.T) {
	input := `{"technique":"steal"}`
	var args getSystemArgs
	err := json.Unmarshal([]byte(input), &args)
	if err != nil {
		t.Fatalf("failed to parse JSON: %v", err)
	}
	if args.Technique != "steal" {
		t.Errorf("Technique = %q, want %q", args.Technique, "steal")
	}

	// Test empty JSON
	input = `{}`
	err = json.Unmarshal([]byte(input), &args)
	if err != nil {
		t.Fatalf("failed to parse empty JSON: %v", err)
	}
}

func TestEnableDebugPrivilege(t *testing.T) {
	// This test will succeed on elevated admin processes and fail otherwise
	// Either way it should not panic
	err := enableDebugPrivilege()
	if err != nil {
		t.Logf("enableDebugPrivilege failed (expected if not admin): %v", err)
	}
}
