package commands

import (
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestWhoCommandName(t *testing.T) {
	cmd := &WhoCommand{}
	if cmd.Name() != "who" {
		t.Errorf("expected 'who', got '%s'", cmd.Name())
	}
}

func TestWhoReturnsOutput(t *testing.T) {
	cmd := &WhoCommand{}
	result := cmd.Execute(structs.Task{})
	// On CI/containers there may be no logged-in users, so just check it doesn't error
	if result.Status != "success" {
		t.Errorf("expected success, got %s: %s", result.Status, result.Output)
	}
}

func TestWhoWithAllFlag(t *testing.T) {
	cmd := &WhoCommand{}
	result := cmd.Execute(structs.Task{Params: `{"all": true}`})
	if result.Status != "success" {
		t.Errorf("expected success, got %s: %s", result.Status, result.Output)
	}
}

func TestWhoHeader(t *testing.T) {
	h := whoHeader()
	if !strings.Contains(h, "USER") {
		t.Error("expected 'USER' in header")
	}
	if !strings.Contains(h, "TTY/SESSION") {
		t.Error("expected 'TTY/SESSION' in header")
	}
	if !strings.Contains(h, "LOGIN TIME") {
		t.Error("expected 'LOGIN TIME' in header")
	}
}

func TestWhoEntry(t *testing.T) {
	entry := whoEntry("testuser", "pts/0", "2026-01-01 12:00:00", "192.168.1.1", "active")
	if !strings.Contains(entry, "testuser") {
		t.Error("expected username in entry")
	}
	if !strings.Contains(entry, "pts/0") {
		t.Error("expected tty in entry")
	}
	if !strings.Contains(entry, "192.168.1.1") {
		t.Error("expected host in entry")
	}
}

func TestWhoEntryDefaults(t *testing.T) {
	entry := whoEntry("user", "", "", "", "")
	if !strings.Contains(entry, "-") {
		t.Error("expected '-' for empty fields")
	}
	if !strings.Contains(entry, "active") {
		t.Error("expected 'active' as default status")
	}
}
