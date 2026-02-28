//go:build !windows

package commands

import (
	"encoding/json"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestSuspendName(t *testing.T) {
	cmd := &SuspendCommand{}
	if cmd.Name() != "suspend" {
		t.Errorf("Expected 'suspend', got '%s'", cmd.Name())
	}
}

func TestSuspendDescription(t *testing.T) {
	cmd := &SuspendCommand{}
	if cmd.Description() == "" {
		t.Error("Description should not be empty")
	}
}

func TestSuspendBadJSON(t *testing.T) {
	cmd := &SuspendCommand{}
	result := cmd.Execute(structs.Task{Params: "not json"})
	if result.Status != "error" {
		t.Error("Expected error for bad JSON")
	}
}

func TestSuspendInvalidPID(t *testing.T) {
	cmd := &SuspendCommand{}

	tests := []struct {
		name string
		pid  int
	}{
		{"zero", 0},
		{"negative", -1},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			params, _ := json.Marshal(SuspendParams{PID: tc.pid})
			result := cmd.Execute(structs.Task{Params: string(params)})
			if result.Status != "error" {
				t.Error("Expected error for invalid PID")
			}
			if !strings.Contains(result.Output, "PID must be greater than 0") {
				t.Errorf("Expected PID error, got: %s", result.Output)
			}
		})
	}
}

func TestSuspendUnknownAction(t *testing.T) {
	cmd := &SuspendCommand{}
	params, _ := json.Marshal(SuspendParams{PID: 12345, Action: "badaction"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Error("Expected error for unknown action")
	}
	if !strings.Contains(result.Output, "Unknown action") {
		t.Errorf("Expected unknown action error, got: %s", result.Output)
	}
}

func TestSuspendDefaultAction(t *testing.T) {
	cmd := &SuspendCommand{}
	// Use a nonexistent PID that won't actually suspend anything
	params, _ := json.Marshal(SuspendParams{PID: 99999999})
	result := cmd.Execute(structs.Task{Params: string(params)})
	// Default action is "suspend" — will fail with ESRCH for nonexistent PID
	if result.Status != "error" {
		t.Errorf("Expected error for nonexistent PID, got %s: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "Failed to suspend") {
		t.Errorf("Expected 'Failed to suspend', got: %s", result.Output)
	}
}

func TestSuspendResumeNonexistent(t *testing.T) {
	cmd := &SuspendCommand{}
	params, _ := json.Marshal(SuspendParams{PID: 99999999, Action: "resume"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("Expected error for nonexistent PID, got %s: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "Failed to resume") {
		t.Errorf("Expected 'Failed to resume', got: %s", result.Output)
	}
}
