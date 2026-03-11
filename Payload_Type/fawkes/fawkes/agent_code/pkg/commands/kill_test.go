//go:build !windows

package commands

import (
	"os"
	"testing"

	"fawkes/pkg/structs"
)

func TestKillCommandName(t *testing.T) {
	cmd := &KillCommand{}
	if cmd.Name() != "kill" {
		t.Errorf("expected 'kill', got %q", cmd.Name())
	}
}

func TestKillCommandDescription(t *testing.T) {
	cmd := &KillCommand{}
	if cmd.Description() == "" {
		t.Error("description should not be empty")
	}
}

func TestKillBadJSON(t *testing.T) {
	cmd := &KillCommand{}
	task := structs.NewTask("t", "kill", "")
	task.Params = "not json"
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Errorf("expected error for bad JSON, got %q", result.Status)
	}
}

func TestKillInvalidPID(t *testing.T) {
	cmd := &KillCommand{}
	task := structs.NewTask("t", "kill", "")
	task.Params = `{"pid":0}`
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Errorf("expected error for PID 0, got %q", result.Status)
	}
}

func TestKillNegativePID(t *testing.T) {
	cmd := &KillCommand{}
	task := structs.NewTask("t", "kill", "")
	task.Params = `{"pid":-1}`
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Errorf("expected error for negative PID, got %q", result.Status)
	}
}

func TestKillNonexistentProcess(t *testing.T) {
	cmd := &KillCommand{}
	task := structs.NewTask("t", "kill", "")
	task.Params = `{"pid":99999}`
	result := cmd.Execute(task)
	// Should error because process likely doesn't exist
	if result.Status != "error" {
		t.Errorf("expected error for nonexistent PID, got %q", result.Status)
	}
}

func TestKillGetProcessNameUnixSelf(t *testing.T) {
	// Current process should always be resolvable
	pid := os.Getpid()
	name := killGetProcessNameUnix(pid)
	if name == "" {
		t.Error("expected process name for current PID, got empty string")
	}
}

func TestKillGetProcessNameUnixInvalid(t *testing.T) {
	// PID 0 (kernel) or very high PID should return empty, not panic
	name := killGetProcessNameUnix(9999999)
	if name != "" {
		t.Errorf("expected empty string for nonexistent PID, got %q", name)
	}
}
