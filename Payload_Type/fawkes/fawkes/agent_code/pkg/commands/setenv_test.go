package commands

import (
	"os"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestSetenvCommandName(t *testing.T) {
	cmd := &SetenvCommand{}
	if cmd.Name() != "setenv" {
		t.Errorf("expected 'setenv', got %q", cmd.Name())
	}
}

func TestSetenvSetJSON(t *testing.T) {
	defer os.Unsetenv("FAWKES_SETENV_TEST")

	cmd := &SetenvCommand{}
	task := structs.NewTask("t", "setenv", "")
	task.Params = `{"action":"set","name":"FAWKES_SETENV_TEST","value":"hello"}`
	result := cmd.Execute(task)
	if result.Status != "success" {
		t.Errorf("expected success, got %q: %s", result.Status, result.Output)
	}
	if os.Getenv("FAWKES_SETENV_TEST") != "hello" {
		t.Error("env var should be set to 'hello'")
	}
}

func TestSetenvUnsetJSON(t *testing.T) {
	os.Setenv("FAWKES_UNSET_TEST", "val")

	cmd := &SetenvCommand{}
	task := structs.NewTask("t", "setenv", "")
	task.Params = `{"action":"unset","name":"FAWKES_UNSET_TEST"}`
	result := cmd.Execute(task)
	if result.Status != "success" {
		t.Errorf("expected success, got %q: %s", result.Status, result.Output)
	}
	if os.Getenv("FAWKES_UNSET_TEST") != "" {
		t.Error("env var should be unset")
	}
}

func TestSetenvSetManual(t *testing.T) {
	defer os.Unsetenv("FAWKES_MANUAL_TEST")

	cmd := &SetenvCommand{}
	task := structs.NewTask("t", "setenv", "")
	task.Params = "set FAWKES_MANUAL_TEST=world"
	result := cmd.Execute(task)
	if result.Status != "success" {
		t.Errorf("expected success, got %q: %s", result.Status, result.Output)
	}
	if os.Getenv("FAWKES_MANUAL_TEST") != "world" {
		t.Error("env var should be set to 'world'")
	}
}

func TestSetenvUnsetManual(t *testing.T) {
	os.Setenv("FAWKES_MANUAL_UNSET", "val")

	cmd := &SetenvCommand{}
	task := structs.NewTask("t", "setenv", "")
	task.Params = "unset FAWKES_MANUAL_UNSET"
	result := cmd.Execute(task)
	if result.Status != "success" {
		t.Errorf("expected success, got %q: %s", result.Status, result.Output)
	}
}

func TestSetenvEmptyName(t *testing.T) {
	cmd := &SetenvCommand{}
	task := structs.NewTask("t", "setenv", "")
	task.Params = `{"action":"set","name":"","value":"x"}`
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Errorf("expected error for empty name, got %q", result.Status)
	}
}

func TestSetenvUnknownAction(t *testing.T) {
	cmd := &SetenvCommand{}
	task := structs.NewTask("t", "setenv", "")
	task.Params = `{"action":"delete","name":"X"}`
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Errorf("expected error for unknown action, got %q", result.Status)
	}
	if !strings.Contains(result.Output, "unknown action") {
		t.Error("output should mention unknown action")
	}
}

func TestSetenvSetMissingEquals(t *testing.T) {
	cmd := &SetenvCommand{}
	task := structs.NewTask("t", "setenv", "")
	task.Params = "set NOEQUALS"
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Errorf("expected error for missing =, got %q", result.Status)
	}
}

func TestSetenvBadManualFormat(t *testing.T) {
	cmd := &SetenvCommand{}
	task := structs.NewTask("t", "setenv", "")
	task.Params = "badformat"
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Errorf("expected error for bad format, got %q", result.Status)
	}
}
