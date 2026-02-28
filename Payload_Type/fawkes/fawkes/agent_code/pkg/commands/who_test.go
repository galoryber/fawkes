package commands

import (
	"encoding/json"
	"testing"

	"fawkes/pkg/structs"
)

func TestWhoCommandName(t *testing.T) {
	cmd := &WhoCommand{}
	if cmd.Name() != "who" {
		t.Errorf("expected 'who', got '%s'", cmd.Name())
	}
}

func TestWhoReturnsJSON(t *testing.T) {
	cmd := &WhoCommand{}
	result := cmd.Execute(structs.Task{})
	if result.Status != "success" {
		t.Errorf("expected success, got %s: %s", result.Status, result.Output)
	}
	// Output should be valid JSON (array or empty array)
	var entries []whoSessionEntry
	if err := json.Unmarshal([]byte(result.Output), &entries); err != nil {
		t.Errorf("expected valid JSON output: %v (got: %s)", err, result.Output)
	}
}

func TestWhoWithAllFlag(t *testing.T) {
	cmd := &WhoCommand{}
	result := cmd.Execute(structs.Task{Params: `{"all": true}`})
	if result.Status != "success" {
		t.Errorf("expected success, got %s: %s", result.Status, result.Output)
	}
	var entries []whoSessionEntry
	if err := json.Unmarshal([]byte(result.Output), &entries); err != nil {
		t.Errorf("expected valid JSON output: %v", err)
	}
}

func TestWhoSessionEntryJSON(t *testing.T) {
	entry := whoSessionEntry{
		User:      "testuser",
		TTY:       "pts/0",
		LoginTime: "2026-01-01 12:00:00",
		From:      "192.168.1.1",
		Status:    "active",
	}
	data, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}
	var decoded whoSessionEntry
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if decoded.User != "testuser" || decoded.TTY != "pts/0" || decoded.From != "192.168.1.1" {
		t.Errorf("unexpected decoded values: %+v", decoded)
	}
}
