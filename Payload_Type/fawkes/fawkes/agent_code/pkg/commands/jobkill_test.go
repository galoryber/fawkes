package commands

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"fawkes/pkg/structs"
)

func TestJobkillName(t *testing.T) {
	cmd := &JobkillCommand{}
	if cmd.Name() != "jobkill" {
		t.Errorf("Expected 'jobkill', got '%s'", cmd.Name())
	}
}

func TestJobkillDescription(t *testing.T) {
	cmd := &JobkillCommand{}
	if cmd.Description() == "" {
		t.Error("Description should not be empty")
	}
}

func TestJobkillBadJSON(t *testing.T) {
	cmd := &JobkillCommand{}
	result := cmd.Execute(structs.Task{Params: "not json"})
	if result.Status != "error" {
		t.Error("Expected error for bad JSON")
	}
	if !strings.Contains(result.Output, "Failed to parse") {
		t.Errorf("Expected parse error, got: %s", result.Output)
	}
}

func TestJobkillMissingID(t *testing.T) {
	cmd := &JobkillCommand{}
	params, _ := json.Marshal(jobkillArgs{})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Error("Expected error for missing ID")
	}
	if !strings.Contains(result.Output, "Task ID is required") {
		t.Errorf("Expected 'Task ID is required', got: %s", result.Output)
	}
}

func TestJobkillTaskNotFound(t *testing.T) {
	cmd := &JobkillCommand{}
	params, _ := json.Marshal(jobkillArgs{ID: "nonexistent-task-id"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Error("Expected error for nonexistent task")
	}
	if !strings.Contains(result.Output, "No running task found") {
		t.Errorf("Expected 'No running task found', got: %s", result.Output)
	}
}

func TestJobkillSuccess(t *testing.T) {
	// Create a task to kill
	target := structs.NewTask("kill-me-123", "portscan", "{}")
	target.StartTime = time.Now()
	TrackTask(&target)
	defer UntrackTask("kill-me-123")

	cmd := &JobkillCommand{}
	params, _ := json.Marshal(jobkillArgs{ID: "kill-me-123"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Errorf("Expected success, got %s: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "Stop signal sent") {
		t.Errorf("Expected 'Stop signal sent', got: %s", result.Output)
	}
	if !strings.Contains(result.Output, "portscan") {
		t.Errorf("Expected command name in output, got: %s", result.Output)
	}

	// Verify the task received the stop signal
	if !target.DidStop() {
		t.Error("Expected task to be stopped after jobkill")
	}
}
