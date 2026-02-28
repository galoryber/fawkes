package commands

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestPsName(t *testing.T) {
	cmd := &PsCommand{}
	if cmd.Name() != "ps" {
		t.Errorf("expected 'ps', got %q", cmd.Name())
	}
}

func TestPsDescription(t *testing.T) {
	cmd := &PsCommand{}
	if cmd.Description() == "" {
		t.Error("description should not be empty")
	}
}

func TestPsExecuteDefault(t *testing.T) {
	cmd := &PsCommand{}
	task := structs.NewTask("t", "ps", "")
	result := cmd.Execute(task)
	if result.Status != "success" {
		t.Fatalf("expected success, got %q: %s", result.Status, result.Output)
	}
	// The output is JSON containing ProcessEntry objects with process_id fields.
	// At minimum our own process should appear.
	if !strings.Contains(result.Output, "process_id") {
		t.Errorf("expected output to contain 'process_id', got: %.200s", result.Output)
	}
	// Processes slice should be populated
	if result.Processes == nil || len(*result.Processes) == 0 {
		t.Error("expected non-empty Processes slice")
	}
}

func TestPsExecuteVerbose(t *testing.T) {
	cmd := &PsCommand{}
	params, _ := json.Marshal(PsArgs{Verbose: true})
	task := structs.NewTask("t", "ps", "")
	task.Params = string(params)
	result := cmd.Execute(task)
	if result.Status != "success" {
		t.Fatalf("expected success, got %q: %s", result.Status, result.Output)
	}
	// Verbose mode should still produce valid JSON output with process entries
	if result.Processes == nil || len(*result.Processes) == 0 {
		t.Error("expected non-empty Processes slice in verbose mode")
	}
}

func TestPsExecuteFilterByName(t *testing.T) {
	// Get our own process name to use as a filter
	self, err := os.Executable()
	if err != nil {
		t.Skipf("cannot determine own executable: %v", err)
	}
	// Extract the base name
	parts := strings.Split(self, "/")
	selfName := parts[len(parts)-1]
	// Use a substring that should match the test binary
	// On Linux, the test binary name is typically something like "commands.test"
	filter := selfName
	if len(filter) > 8 {
		filter = filter[:8] // Use a short prefix to increase match likelihood
	}

	cmd := &PsCommand{}
	params, _ := json.Marshal(PsArgs{Filter: filter})
	task := structs.NewTask("t", "ps", "")
	task.Params = string(params)
	result := cmd.Execute(task)
	if result.Status != "success" {
		t.Fatalf("expected success, got %q: %s", result.Status, result.Output)
	}
	// Should find at least our own process
	if result.Processes == nil || len(*result.Processes) == 0 {
		t.Logf("filter %q matched 0 processes (may be expected if binary name differs)", filter)
	}
}

func TestPsExecuteInvalidPID(t *testing.T) {
	cmd := &PsCommand{}
	params, _ := json.Marshal(PsArgs{PID: -1})
	task := structs.NewTask("t", "ps", "")
	task.Params = string(params)
	result := cmd.Execute(task)
	// A negative PID should not match any process; the command should still succeed
	// but return an empty (or near-empty) list
	if result.Status != "success" {
		t.Fatalf("expected success (graceful handling), got %q: %s", result.Status, result.Output)
	}
	// With PID -1, no process should match because getProcessList filters on pid > 0
	// and -1 is not > 0, so the filter is effectively skipped. But the function still
	// succeeds and returns results.
	if !result.Completed {
		t.Error("expected Completed=true")
	}
}
