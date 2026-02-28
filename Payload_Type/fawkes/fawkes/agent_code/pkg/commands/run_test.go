//go:build !windows

package commands

import (
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestRunName(t *testing.T) {
	cmd := &RunCommand{}
	if cmd.Name() != "run" {
		t.Errorf("expected 'run', got '%s'", cmd.Name())
	}
}

func TestRunDescription(t *testing.T) {
	cmd := &RunCommand{}
	if cmd.Description() == "" {
		t.Error("expected non-empty description")
	}
}

func TestRunNoParams(t *testing.T) {
	cmd := &RunCommand{}
	result := cmd.Execute(structs.Task{})
	if result.Status != "error" {
		t.Errorf("expected error for empty params, got %s", result.Status)
	}
	if !strings.Contains(result.Output, "No command") {
		t.Errorf("expected 'No command' error, got: %s", result.Output)
	}
}

func TestRunEcho(t *testing.T) {
	cmd := &RunCommand{}
	result := cmd.Execute(structs.Task{Params: "echo hello_world_test"})
	if result.Status != "success" {
		t.Errorf("expected success, got %s: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "hello_world_test") {
		t.Errorf("expected 'hello_world_test' in output, got: %s", result.Output)
	}
}

func TestRunNoOutput(t *testing.T) {
	cmd := &RunCommand{}
	result := cmd.Execute(structs.Task{Params: "true"})
	if result.Status != "success" {
		t.Errorf("expected success, got %s: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "no output") {
		t.Errorf("expected 'no output' message, got: %s", result.Output)
	}
}

func TestRunFailingCommand(t *testing.T) {
	cmd := &RunCommand{}
	result := cmd.Execute(structs.Task{Params: "false"})
	if result.Status != "error" {
		t.Errorf("expected error for failing command, got %s", result.Status)
	}
}
