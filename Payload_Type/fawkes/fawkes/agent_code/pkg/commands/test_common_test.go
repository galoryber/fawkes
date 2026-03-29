package commands

import (
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

// mockTask creates a Task with properly initialized fields for testing.
func mockTask(command, params string) structs.Task {
	return structs.NewTask("test-task-id", command, params)
}

// assertSuccess fails the test if the result status is not "success".
func assertSuccess(t *testing.T, result structs.CommandResult) {
	t.Helper()
	if result.Status != "success" {
		t.Errorf("expected status \"success\", got %q: %s", result.Status, result.Output)
	}
}

// assertError fails the test if the result status is not "error".
func assertError(t *testing.T, result structs.CommandResult) {
	t.Helper()
	if result.Status != "error" {
		t.Errorf("expected status \"error\", got %q: %s", result.Status, result.Output)
	}
}

// assertOutputContains fails the test if the output does not contain the substring.
func assertOutputContains(t *testing.T, result structs.CommandResult, substr string) {
	t.Helper()
	if !strings.Contains(result.Output, substr) {
		t.Errorf("expected output to contain %q, got %q", substr, result.Output)
	}
}

// assertOutputNotContains fails the test if the output contains the substring.
func assertOutputNotContains(t *testing.T, result structs.CommandResult, substr string) {
	t.Helper()
	if strings.Contains(result.Output, substr) {
		t.Errorf("expected output to NOT contain %q, got %q", substr, result.Output)
	}
}

// assertCommandName verifies the command's Name() returns the expected value.
func assertCommandName(t *testing.T, cmd structs.Command, expected string) {
	t.Helper()
	if cmd.Name() != expected {
		t.Errorf("expected command name %q, got %q", expected, cmd.Name())
	}
}

// assertCommandHasDescription verifies the command's Description() is non-empty.
func assertCommandHasDescription(t *testing.T, cmd structs.Command) {
	t.Helper()
	if cmd.Description() == "" {
		t.Errorf("expected non-empty description for command %q", cmd.Name())
	}
}

// assertEmptyParamsError verifies that executing a command with empty params returns an error.
func assertEmptyParamsError(t *testing.T, cmd structs.Command) {
	t.Helper()
	task := mockTask(cmd.Name(), "")
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Errorf("expected error for empty params, got %q: %s", result.Status, result.Output)
	}
}

// newTestAgent creates a test Agent with sensible defaults for unit tests.
func newTestAgent() *structs.Agent {
	return &structs.Agent{
		PayloadUUID:   "test-uuid-1234",
		Host:          "testhost",
		User:          "testuser",
		OS:            "linux",
		Architecture:  "amd64",
		PID:           12345,
		ProcessName:   "agent",
		InternalIP:    "192.168.1.100",
		Integrity:     3,
		SleepInterval: 30,
		Jitter:        20,
	}
}
