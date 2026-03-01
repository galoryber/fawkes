package commands

import (
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestHistoryScrubName(t *testing.T) {
	cmd := &HistoryScrubCommand{}
	if cmd.Name() != "history-scrub" {
		t.Errorf("expected 'history-scrub', got '%s'", cmd.Name())
	}
}

func TestHistoryScrubDescription(t *testing.T) {
	cmd := &HistoryScrubCommand{}
	if cmd.Description() == "" {
		t.Error("expected non-empty description")
	}
}

func TestHistoryScrubDefaultAction(t *testing.T) {
	cmd := &HistoryScrubCommand{}
	// Empty params defaults to "list" action
	result := cmd.Execute(structs.Task{})
	if result.Status != "success" {
		t.Errorf("expected success for default list action, got %s: %s", result.Status, result.Output)
	}
}

func TestHistoryScrubListAction(t *testing.T) {
	cmd := &HistoryScrubCommand{}
	result := cmd.Execute(structs.Task{Params: `{"action":"list"}`})
	if result.Status != "success" {
		t.Errorf("expected success, got %s: %s", result.Status, result.Output)
	}
}

func TestHistoryScrubBadJSON(t *testing.T) {
	cmd := &HistoryScrubCommand{}
	result := cmd.Execute(structs.Task{Params: "not-json"})
	if result.Status != "error" {
		t.Errorf("expected error for bad JSON, got %s", result.Status)
	}
}

func TestHistoryScrubInvalidAction(t *testing.T) {
	cmd := &HistoryScrubCommand{}
	result := cmd.Execute(structs.Task{Params: `{"action":"invalid"}`})
	if result.Status != "error" {
		t.Errorf("expected error for invalid action, got %s", result.Status)
	}
	if !strings.Contains(result.Output, "Unknown action") {
		t.Errorf("expected 'Unknown action' message, got: %s", result.Output)
	}
}
