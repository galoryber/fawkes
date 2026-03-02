//go:build windows

package commands

import (
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
