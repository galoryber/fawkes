package commands

import (
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestProcessTreeBasic(t *testing.T) {
	cmd := &ProcessTreeCommand{}
	result := cmd.Execute(structs.Task{Params: "{}"})

	if result.Status != "success" {
		t.Fatalf("expected success, got %s: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "processes") {
		t.Fatalf("expected process count, got: %s", result.Output[:200])
	}
	// Should contain tree connectors
	if !strings.Contains(result.Output, "|--") && !strings.Contains(result.Output, "`--") {
		t.Fatalf("expected tree connectors, got: %s", result.Output[:500])
	}
}

func TestProcessTreeWithPID(t *testing.T) {
	// PID 1 should exist on Linux
	cmd := &ProcessTreeCommand{}
	result := cmd.Execute(structs.Task{Params: `{"pid": 1}`})

	if result.Status != "success" {
		t.Fatalf("expected success, got %s: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "1:") {
		t.Fatalf("expected PID 1 in output, got: %s", result.Output[:200])
	}
}

func TestProcessTreeBadPID(t *testing.T) {
	cmd := &ProcessTreeCommand{}
	result := cmd.Execute(structs.Task{Params: `{"pid": 99999999}`})

	if result.Status != "error" {
		t.Fatalf("expected error for nonexistent PID, got %s", result.Status)
	}
}

func TestProcessTreeNoParams(t *testing.T) {
	cmd := &ProcessTreeCommand{}
	result := cmd.Execute(structs.Task{Params: ""})

	// Should still work with no params (show all)
	if result.Status != "success" {
		t.Fatalf("expected success with no params, got %s: %s", result.Status, result.Output)
	}
}
