//go:build !windows

package commands

import (
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestCrontabName(t *testing.T) {
	cmd := &CrontabCommand{}
	if cmd.Name() != "crontab" {
		t.Errorf("expected 'crontab', got '%s'", cmd.Name())
	}
}

func TestCrontabDescription(t *testing.T) {
	cmd := &CrontabCommand{}
	if cmd.Description() == "" {
		t.Error("expected non-empty description")
	}
}

func TestCrontabEmptyParams(t *testing.T) {
	cmd := &CrontabCommand{}
	result := cmd.Execute(structs.Task{})
	if result.Status != "error" {
		t.Errorf("expected error for empty params, got %s", result.Status)
	}
	if !strings.Contains(result.Output, "parameters required") {
		t.Errorf("expected 'parameters required' error, got: %s", result.Output)
	}
}

func TestCrontabBadJSON(t *testing.T) {
	cmd := &CrontabCommand{}
	result := cmd.Execute(structs.Task{Params: "not-json"})
	if result.Status != "error" {
		t.Errorf("expected error for bad JSON, got %s", result.Status)
	}
}

func TestCrontabInvalidAction(t *testing.T) {
	cmd := &CrontabCommand{}
	result := cmd.Execute(structs.Task{Params: `{"action":"invalid"}`})
	if result.Status != "error" {
		t.Errorf("expected error for invalid action, got %s", result.Status)
	}
	if !strings.Contains(result.Output, "Unknown action") {
		t.Errorf("expected 'Unknown action' message, got: %s", result.Output)
	}
}

func TestCrontabList(t *testing.T) {
	cmd := &CrontabCommand{}
	result := cmd.Execute(structs.Task{Params: `{"action":"list"}`})
	// Should succeed even if no crontab exists
	if result.Status != "success" {
		t.Errorf("expected success for list, got %s: %s", result.Status, result.Output)
	}
}
