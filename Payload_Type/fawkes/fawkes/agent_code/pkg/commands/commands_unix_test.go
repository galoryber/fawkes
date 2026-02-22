//go:build !windows

package commands

import (
	"encoding/json"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

// =============================================================================
// crontab command parameter parsing tests
// =============================================================================

func TestCrontabCommand_Name(t *testing.T) {
	cmd := &CrontabCommand{}
	if cmd.Name() != "crontab" {
		t.Errorf("Name() = %q, want %q", cmd.Name(), "crontab")
	}
	if cmd.Description() == "" {
		t.Error("Description() should not be empty")
	}
}

func TestCrontabCommand_EmptyParams(t *testing.T) {
	cmd := &CrontabCommand{}
	task := structs.Task{Params: ""}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Errorf("expected error for empty params, got %q", result.Status)
	}
}

func TestCrontabCommand_InvalidJSON(t *testing.T) {
	cmd := &CrontabCommand{}
	task := structs.Task{Params: "not json"}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Errorf("expected error for invalid JSON, got %q", result.Status)
	}
}

func TestCrontabCommand_UnknownAction(t *testing.T) {
	cmd := &CrontabCommand{}
	params, _ := json.Marshal(map[string]string{"action": "restart"})
	task := structs.Task{Params: string(params)}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Errorf("expected error for unknown action, got %q", result.Status)
	}
	if !strings.Contains(result.Output, "restart") {
		t.Errorf("error should mention the bad action, got: %s", result.Output)
	}
}

func TestCrontabCommand_ListAction(t *testing.T) {
	cmd := &CrontabCommand{}
	params, _ := json.Marshal(map[string]string{"action": "list"})
	task := structs.Task{Params: string(params)}
	result := cmd.Execute(task)

	// Should succeed even if no crontab exists
	if result.Status != "success" && result.Status != "error" {
		t.Errorf("unexpected status %q: %s", result.Status, result.Output)
	}
}

func TestCrontabCommand_AddMissingProgram(t *testing.T) {
	cmd := &CrontabCommand{}
	params, _ := json.Marshal(map[string]string{"action": "add"})
	task := structs.Task{Params: string(params)}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Errorf("expected error for add without entry/program, got %q", result.Status)
	}
}

func TestCrontabCommand_RemoveMissingEntry(t *testing.T) {
	cmd := &CrontabCommand{}
	params, _ := json.Marshal(map[string]string{"action": "remove"})
	task := structs.Task{Params: string(params)}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Errorf("expected error for remove without entry/program, got %q", result.Status)
	}
}

// =============================================================================
// ssh-keys command parameter parsing tests
// =============================================================================

func TestSSHKeysCommand_Name(t *testing.T) {
	cmd := &SSHKeysCommand{}
	if cmd.Name() != "ssh-keys" {
		t.Errorf("Name() = %q, want %q", cmd.Name(), "ssh-keys")
	}
	if cmd.Description() == "" {
		t.Error("Description() should not be empty")
	}
}

func TestSSHKeysCommand_EmptyParams(t *testing.T) {
	cmd := &SSHKeysCommand{}
	task := structs.Task{Params: ""}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Errorf("expected error for empty params, got %q", result.Status)
	}
}

func TestSSHKeysCommand_InvalidJSON(t *testing.T) {
	cmd := &SSHKeysCommand{}
	task := structs.Task{Params: "not json"}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Errorf("expected error for invalid JSON, got %q", result.Status)
	}
}

func TestSSHKeysCommand_UnknownAction(t *testing.T) {
	cmd := &SSHKeysCommand{}
	params, _ := json.Marshal(map[string]string{"action": "delete"})
	task := structs.Task{Params: string(params)}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Errorf("expected error for unknown action, got %q", result.Status)
	}
	if !strings.Contains(result.Output, "delete") {
		t.Errorf("error should mention the bad action, got: %s", result.Output)
	}
}

func TestSSHKeysCommand_ListAction(t *testing.T) {
	cmd := &SSHKeysCommand{}
	params, _ := json.Marshal(map[string]string{"action": "list"})
	task := structs.Task{Params: string(params)}
	result := cmd.Execute(task)

	// Should succeed or error gracefully depending on whether .ssh exists
	if !result.Completed {
		t.Error("expected Completed=true")
	}
}

// =============================================================================
// Unix platform registration test
// =============================================================================

func TestUnixCommandsRegistered(t *testing.T) {
	Initialize()
	unixCmds := []string{"crontab", "ssh-keys"}
	for _, name := range unixCmds {
		cmd := GetCommand(name)
		if cmd == nil {
			t.Errorf("GetCommand(%q) = nil after Initialize", name)
		}
	}
}
