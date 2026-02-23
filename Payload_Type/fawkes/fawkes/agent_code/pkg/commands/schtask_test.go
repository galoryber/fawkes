//go:build windows
// +build windows

package commands

import (
	"encoding/json"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestSchtaskCommand_Name(t *testing.T) {
	cmd := &SchtaskCommand{}
	if cmd.Name() != "schtask" {
		t.Errorf("expected 'schtask', got '%s'", cmd.Name())
	}
}

func TestSchtaskCommand_Description(t *testing.T) {
	cmd := &SchtaskCommand{}
	if !strings.Contains(cmd.Description(), "COM API") {
		t.Errorf("description should mention COM API, got '%s'", cmd.Description())
	}
}

func TestSchtaskCommand_EmptyParams(t *testing.T) {
	cmd := &SchtaskCommand{}
	result := cmd.Execute(structs.Task{Params: ""})
	if result.Status != "error" {
		t.Error("expected error for empty params")
	}
}

func TestSchtaskCommand_InvalidJSON(t *testing.T) {
	cmd := &SchtaskCommand{}
	result := cmd.Execute(structs.Task{Params: "{bad"})
	if result.Status != "error" {
		t.Error("expected error for invalid JSON")
	}
}

func TestSchtaskCommand_UnknownAction(t *testing.T) {
	cmd := &SchtaskCommand{}
	params, _ := json.Marshal(schtaskArgs{Action: "invalid"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Error("expected error for unknown action")
	}
	if !strings.Contains(result.Output, "Unknown action") {
		t.Errorf("expected unknown action message, got '%s'", result.Output)
	}
}

func TestSchtaskCommand_CreateNoName(t *testing.T) {
	cmd := &SchtaskCommand{}
	params, _ := json.Marshal(schtaskArgs{Action: "create"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Error("expected error when name is empty")
	}
	if !strings.Contains(result.Output, "name is required") {
		t.Errorf("expected name required message, got '%s'", result.Output)
	}
}

func TestSchtaskCommand_CreateNoProgram(t *testing.T) {
	cmd := &SchtaskCommand{}
	params, _ := json.Marshal(schtaskArgs{Action: "create", Name: "TestTask"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Error("expected error when program is empty")
	}
	if !strings.Contains(result.Output, "program is required") {
		t.Errorf("expected program required message, got '%s'", result.Output)
	}
}

func TestSchtaskCommand_QueryNoName(t *testing.T) {
	cmd := &SchtaskCommand{}
	params, _ := json.Marshal(schtaskArgs{Action: "query"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Error("expected error when name is empty")
	}
}

func TestSchtaskCommand_DeleteNoName(t *testing.T) {
	cmd := &SchtaskCommand{}
	params, _ := json.Marshal(schtaskArgs{Action: "delete"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Error("expected error when name is empty")
	}
}

func TestSchtaskCommand_RunNoName(t *testing.T) {
	cmd := &SchtaskCommand{}
	params, _ := json.Marshal(schtaskArgs{Action: "run"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Error("expected error when name is empty")
	}
}

func TestSchtaskCommand_List(t *testing.T) {
	cmd := &SchtaskCommand{}
	params, _ := json.Marshal(schtaskArgs{Action: "list"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Errorf("expected success for list, got '%s': %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "Scheduled Tasks") {
		t.Errorf("expected scheduled tasks header, got '%s'", result.Output)
	}
}

func TestTriggerTypeFromString(t *testing.T) {
	tests := []struct {
		input    string
		expected int
	}{
		{"ONLOGON", TASK_TRIGGER_LOGON},
		{"onlogon", TASK_TRIGGER_LOGON},
		{"ONSTART", TASK_TRIGGER_BOOT},
		{"DAILY", TASK_TRIGGER_DAILY},
		{"WEEKLY", TASK_TRIGGER_WEEKLY},
		{"ONIDLE", TASK_TRIGGER_IDLE},
		{"ONCE", TASK_TRIGGER_TIME},
		{"unknown", TASK_TRIGGER_LOGON}, // default
	}

	for _, tt := range tests {
		result := triggerTypeFromString(tt.input)
		if result != tt.expected {
			t.Errorf("triggerTypeFromString(%q) = %d, want %d", tt.input, result, tt.expected)
		}
	}
}

func TestTaskStateIntToString(t *testing.T) {
	tests := []struct {
		input    int
		expected string
	}{
		{0, "Unknown"},
		{1, "Disabled"},
		{2, "Queued"},
		{3, "Ready"},
		{4, "Running"},
		{99, "Unknown(99)"},
	}

	for _, tt := range tests {
		result := taskStateIntToString(tt.input)
		if result != tt.expected {
			t.Errorf("taskStateIntToString(%d) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestTaskStateToString_Types(t *testing.T) {
	// Test int32
	result := taskStateToString(int32(3))
	if result != "Ready" {
		t.Errorf("taskStateToString(int32(3)) = %q, want 'Ready'", result)
	}

	// Test int64
	result = taskStateToString(int64(4))
	if result != "Running" {
		t.Errorf("taskStateToString(int64(4)) = %q, want 'Running'", result)
	}

	// Test int
	result = taskStateToString(1)
	if result != "Disabled" {
		t.Errorf("taskStateToString(1) = %q, want 'Disabled'", result)
	}

	// Test string fallback
	result = taskStateToString("some string")
	if result != "some string" {
		t.Errorf("taskStateToString(\"some string\") = %q, want 'some string'", result)
	}
}

// Integration test: create → query → run → delete lifecycle
func TestSchtaskCommand_Lifecycle(t *testing.T) {
	cmd := &SchtaskCommand{}
	taskName := "FawkesUnitTest_schtask"

	// Create
	createParams, _ := json.Marshal(schtaskArgs{
		Action:  "create",
		Name:    taskName,
		Program: "cmd.exe",
		Args:    "/c echo test",
		Trigger: "ONCE",
	})
	result := cmd.Execute(structs.Task{Params: string(createParams)})
	if result.Status != "success" {
		t.Fatalf("create failed: %s", result.Output)
	}
	if !strings.Contains(result.Output, "Created scheduled task") {
		t.Errorf("expected creation message, got '%s'", result.Output)
	}

	// Query
	queryParams, _ := json.Marshal(schtaskArgs{
		Action: "query",
		Name:   taskName,
	})
	result = cmd.Execute(structs.Task{Params: string(queryParams)})
	if result.Status != "success" {
		t.Fatalf("query failed: %s", result.Output)
	}
	if !strings.Contains(result.Output, taskName) {
		t.Errorf("expected task name in output, got '%s'", result.Output)
	}

	// Delete (cleanup)
	deleteParams, _ := json.Marshal(schtaskArgs{
		Action: "delete",
		Name:   taskName,
	})
	result = cmd.Execute(structs.Task{Params: string(deleteParams)})
	if result.Status != "success" {
		t.Fatalf("delete failed: %s", result.Output)
	}
	if !strings.Contains(result.Output, "Deleted") {
		t.Errorf("expected deletion message, got '%s'", result.Output)
	}
}
