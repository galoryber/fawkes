package commands

import (
	"runtime"
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

func TestGetTargetHome_WithUser(t *testing.T) {
	result := getTargetHome("testuser")
	if runtime.GOOS == "windows" {
		if result != `C:\Users\testuser` {
			t.Errorf("expected Windows path, got %q", result)
		}
	} else {
		if result != "/home/testuser" {
			t.Errorf("expected /home/testuser, got %q", result)
		}
	}
}

func TestGetTargetHome_EmptyUser(t *testing.T) {
	result := getTargetHome("")
	if result == "" {
		t.Error("expected non-empty home directory for current user")
	}
}

func TestHistoryTargets_NonEmpty(t *testing.T) {
	home := getTargetHome("")
	targets := historyTargets(home)
	if len(targets) == 0 {
		t.Error("expected at least one history target")
	}
	for _, tgt := range targets {
		if tgt.path == "" {
			t.Error("target path should not be empty")
		}
		if tgt.htype == "" {
			t.Error("target type should not be empty")
		}
	}
}
