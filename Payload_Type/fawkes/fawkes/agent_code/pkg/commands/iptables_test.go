//go:build linux

package commands

import (
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestIptablesName(t *testing.T) {
	cmd := &IptablesCommand{}
	if cmd.Name() != "iptables" {
		t.Errorf("expected 'iptables', got %q", cmd.Name())
	}
}

func TestIptablesEmptyParams(t *testing.T) {
	cmd := &IptablesCommand{}
	result := cmd.Execute(structs.Task{Params: ""})
	if result.Status != "error" {
		t.Errorf("expected error, got %s", result.Status)
	}
}

func TestIptablesBadJSON(t *testing.T) {
	cmd := &IptablesCommand{}
	result := cmd.Execute(structs.Task{Params: "not json"})
	if result.Status != "error" {
		t.Errorf("expected error, got %s", result.Status)
	}
}

func TestIptablesInvalidAction(t *testing.T) {
	cmd := &IptablesCommand{}
	result := cmd.Execute(structs.Task{Params: `{"action":"invalid"}`})
	if result.Status != "error" || !strings.Contains(result.Output, "Unknown action") {
		t.Errorf("expected unknown action error, got %s: %s", result.Status, result.Output)
	}
}

func TestIptablesStatus(t *testing.T) {
	cmd := &IptablesCommand{}
	result := cmd.Execute(structs.Task{Params: `{"action":"status"}`})
	if result.Status != "success" {
		t.Errorf("expected success, got %s: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "Linux Firewall Status") {
		t.Errorf("expected 'Linux Firewall Status' in output, got: %s", result.Output)
	}
	if !strings.Contains(result.Output, "IP Forwarding") {
		t.Errorf("expected 'IP Forwarding' in output, got: %s", result.Output)
	}
}

func TestIptablesAddMissingRule(t *testing.T) {
	cmd := &IptablesCommand{}
	result := cmd.Execute(structs.Task{Params: `{"action":"add"}`})
	if result.Status != "error" || !strings.Contains(result.Output, "rule parameter required") {
		t.Errorf("expected rule required error, got %s: %s", result.Status, result.Output)
	}
}

func TestIptablesDeleteMissingRule(t *testing.T) {
	cmd := &IptablesCommand{}
	result := cmd.Execute(structs.Task{Params: `{"action":"delete"}`})
	if result.Status != "error" || !strings.Contains(result.Output, "rule parameter required") {
		t.Errorf("expected rule required error, got %s: %s", result.Status, result.Output)
	}
}

func TestIptablesRules(t *testing.T) {
	cmd := &IptablesCommand{}
	result := cmd.Execute(structs.Task{Params: `{"action":"rules"}`})
	// Should succeed even if iptables not installed (will report error in output)
	if result.Status != "success" {
		t.Errorf("expected success, got %s: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "iptables rules") {
		t.Errorf("expected 'iptables rules' in output, got: %s", result.Output)
	}
}

func TestIptablesNAT(t *testing.T) {
	cmd := &IptablesCommand{}
	result := cmd.Execute(structs.Task{Params: `{"action":"nat"}`})
	if result.Status != "success" {
		t.Errorf("expected success, got %s: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "NAT Rules") {
		t.Errorf("expected 'NAT Rules' in output, got: %s", result.Output)
	}
}
