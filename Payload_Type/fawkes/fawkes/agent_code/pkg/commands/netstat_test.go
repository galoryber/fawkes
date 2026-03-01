package commands

import (
	"encoding/json"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestNetstatName(t *testing.T) {
	cmd := &NetstatCommand{}
	if cmd.Name() != "net-stat" {
		t.Errorf("expected 'net-stat', got '%s'", cmd.Name())
	}
}

func TestNetstatDescription(t *testing.T) {
	cmd := &NetstatCommand{}
	if cmd.Description() == "" {
		t.Error("expected non-empty description")
	}
}

func TestNetstatDefault(t *testing.T) {
	cmd := &NetstatCommand{}
	result := cmd.Execute(structs.Task{})
	if result.Status != "success" {
		t.Errorf("expected success, got %s: %s", result.Status, result.Output)
	}
	// Output should be valid JSON
	var entries []netstatEntry
	if err := json.Unmarshal([]byte(result.Output), &entries); err != nil {
		t.Errorf("expected valid JSON output, got error: %v\nOutput: %s", err, result.Output[:min(200, len(result.Output))])
	}
}

func TestNetstatContainsConnections(t *testing.T) {
	cmd := &NetstatCommand{}
	result := cmd.Execute(structs.Task{})
	if result.Status != "success" {
		t.Skipf("netstat failed (may need elevated perms): %s", result.Output)
	}
	var entries []netstatEntry
	if err := json.Unmarshal([]byte(result.Output), &entries); err != nil {
		t.Fatalf("failed to parse JSON: %v", err)
	}
	// Should have at least one connection on any running system
	if len(entries) == 0 {
		t.Log("no connections found (may be expected in test env)")
		return
	}
	// Check that proto is TCP or UDP
	for _, e := range entries {
		if e.Proto != "TCP" && e.Proto != "UDP" {
			if !strings.HasPrefix(e.Proto, "TCP") && !strings.HasPrefix(e.Proto, "UDP") {
				t.Logf("unexpected proto: %s", e.Proto)
			}
		}
	}
}

func TestNetstatJSONFields(t *testing.T) {
	cmd := &NetstatCommand{}
	result := cmd.Execute(structs.Task{})
	if result.Status != "success" {
		t.Skipf("netstat failed: %s", result.Output)
	}
	var entries []netstatEntry
	if err := json.Unmarshal([]byte(result.Output), &entries); err != nil {
		t.Fatalf("failed to parse JSON: %v", err)
	}
	if len(entries) == 0 {
		t.Skip("no connections to validate")
	}
	// Verify first entry has expected fields populated
	e := entries[0]
	if e.Proto == "" {
		t.Error("expected non-empty proto field")
	}
	if e.LocalIP == "" {
		t.Error("expected non-empty local_ip field")
	}
	if e.State == "" {
		t.Error("expected non-empty state field")
	}
}
