//go:build windows

package commands

import (
	"encoding/json"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestNamedPipesCommand_NameAndDescription(t *testing.T) {
	cmd := &NamedPipesCommand{}
	if cmd.Name() != "named-pipes" {
		t.Errorf("Name() = %q, want %q", cmd.Name(), "named-pipes")
	}
	if cmd.Description() == "" {
		t.Error("Description() should not be empty")
	}
}

func TestNamedPipesCommand_InvalidJSON(t *testing.T) {
	cmd := &NamedPipesCommand{}
	result := cmd.Execute(structs.Task{Params: "not json"})
	if result.Status != "error" {
		t.Errorf("expected error for invalid JSON, got %q", result.Status)
	}
	if !result.Completed {
		t.Error("expected Completed=true")
	}
}

func TestNamedPipesCommand_ListAll(t *testing.T) {
	cmd := &NamedPipesCommand{}
	result := cmd.Execute(structs.Task{Params: ""})

	if result.Status != "success" {
		t.Errorf("expected success, got %q: %s", result.Status, result.Output)
	}
	if !result.Completed {
		t.Error("expected Completed=true")
	}

	// Should contain pipe count
	if !strings.Contains(result.Output, "Named pipes:") {
		t.Error("output should contain 'Named pipes:' count")
	}

	// Should contain at least some well-known pipes
	if !strings.Contains(result.Output, `\\.\pipe\`) {
		t.Error("output should contain pipe path prefix")
	}
}

func TestNamedPipesCommand_FilterMatch(t *testing.T) {
	cmd := &NamedPipesCommand{}
	// Filter for "lsass" or "svc" which are common Windows pipes
	params, _ := json.Marshal(namedPipesArgs{Filter: "lsass"})
	result := cmd.Execute(structs.Task{Params: string(params)})

	if result.Status != "success" {
		t.Errorf("expected success, got %q: %s", result.Status, result.Output)
	}

	if !strings.Contains(result.Output, "Filter: lsass") {
		t.Error("output should show the applied filter")
	}
}

func TestNamedPipesCommand_FilterNoMatch(t *testing.T) {
	cmd := &NamedPipesCommand{}
	params, _ := json.Marshal(namedPipesArgs{Filter: "NONEXISTENTPIPE12345"})
	result := cmd.Execute(structs.Task{Params: string(params)})

	if result.Status != "success" {
		t.Errorf("expected success even with no matches, got %q: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "Named pipes: 0") {
		t.Error("no pipes should match nonexistent filter")
	}
}

func TestNamedPipesArgs_JSONParsing(t *testing.T) {
	input := `{"filter":"spool"}`
	var args namedPipesArgs
	err := json.Unmarshal([]byte(input), &args)
	if err != nil {
		t.Fatalf("failed to parse JSON: %v", err)
	}
	if args.Filter != "spool" {
		t.Errorf("Filter = %q, want %q", args.Filter, "spool")
	}

	// Test empty JSON
	input = `{}`
	err = json.Unmarshal([]byte(input), &args)
	if err != nil {
		t.Fatalf("failed to parse empty JSON: %v", err)
	}
}
