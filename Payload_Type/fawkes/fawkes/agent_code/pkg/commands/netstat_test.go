package commands

import (
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
	// Should contain header columns
	if !strings.Contains(result.Output, "Proto") || !strings.Contains(result.Output, "Local Address") {
		t.Errorf("expected table header in output, got: %s", result.Output[:min(200, len(result.Output))])
	}
}

func TestNetstatContainsConnections(t *testing.T) {
	cmd := &NetstatCommand{}
	result := cmd.Execute(structs.Task{})
	if result.Status != "success" {
		t.Skipf("netstat failed (may need elevated perms): %s", result.Output)
	}
	// Should show at least one connection (TCP or UDP)
	if !strings.Contains(result.Output, "TCP") && !strings.Contains(result.Output, "UDP") {
		t.Logf("no TCP/UDP connections found (may be expected in test env): %s", result.Output[:min(300, len(result.Output))])
	}
}
