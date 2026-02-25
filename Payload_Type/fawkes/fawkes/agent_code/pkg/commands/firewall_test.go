//go:build windows
// +build windows

package commands

import (
	"encoding/json"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestFirewallNameAndDescription(t *testing.T) {
	cmd := &FirewallCommand{}
	if cmd.Name() != "firewall" {
		t.Errorf("Expected name 'firewall', got '%s'", cmd.Name())
	}
	if cmd.Description() == "" {
		t.Error("Description should not be empty")
	}
}

func TestFirewallInvalidJSON(t *testing.T) {
	cmd := &FirewallCommand{}
	task := structs.Task{Params: "not json"}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Error("Expected error status for invalid JSON")
	}
	if !strings.Contains(result.Output, "Error parsing parameters") {
		t.Errorf("Expected parsing error, got: %s", result.Output)
	}
}

func TestFirewallEmptyParams(t *testing.T) {
	cmd := &FirewallCommand{}
	task := structs.Task{Params: ""}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Error("Expected error for empty params")
	}
	if !strings.Contains(result.Output, "parameters required") {
		t.Errorf("Expected parameters required error, got: %s", result.Output)
	}
}

func TestFirewallUnknownAction(t *testing.T) {
	cmd := &FirewallCommand{}
	params, _ := json.Marshal(map[string]string{"action": "nonexistent"})
	task := structs.Task{Params: string(params)}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Error("Expected error for unknown action")
	}
	if !strings.Contains(result.Output, "Unknown action") {
		t.Errorf("Expected unknown action error, got: %s", result.Output)
	}
}

func TestFirewallAddMissingName(t *testing.T) {
	cmd := &FirewallCommand{}
	params, _ := json.Marshal(map[string]string{"action": "add"})
	task := structs.Task{Params: string(params)}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Error("Expected error for add without name")
	}
	if !strings.Contains(result.Output, "name is required") {
		t.Errorf("Expected name required error, got: %s", result.Output)
	}
}

func TestFirewallDeleteMissingName(t *testing.T) {
	cmd := &FirewallCommand{}
	params, _ := json.Marshal(map[string]string{"action": "delete"})
	task := structs.Task{Params: string(params)}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Error("Expected error for delete without name")
	}
	if !strings.Contains(result.Output, "name is required") {
		t.Errorf("Expected name required error, got: %s", result.Output)
	}
}

func TestFirewallEnableMissingName(t *testing.T) {
	cmd := &FirewallCommand{}
	params, _ := json.Marshal(map[string]string{"action": "enable"})
	task := structs.Task{Params: string(params)}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Error("Expected error for enable without name")
	}
	if !strings.Contains(result.Output, "name is required") {
		t.Errorf("Expected name required error, got: %s", result.Output)
	}
}

func TestFirewallDisableMissingName(t *testing.T) {
	cmd := &FirewallCommand{}
	params, _ := json.Marshal(map[string]string{"action": "disable"})
	task := structs.Task{Params: string(params)}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Error("Expected error for disable without name")
	}
	if !strings.Contains(result.Output, "name is required") {
		t.Errorf("Expected name required error, got: %s", result.Output)
	}
}

func TestFirewallActionNormalization(t *testing.T) {
	cmd := &FirewallCommand{}
	// Test uppercase action - should not fail with "Unknown action"
	params, _ := json.Marshal(map[string]string{"action": "STATUS"})
	task := structs.Task{Params: string(params)}
	result := cmd.Execute(task)
	if strings.Contains(result.Output, "Unknown action") {
		t.Error("Action should be case-insensitive")
	}
}

func TestFirewallHelperFunctions(t *testing.T) {
	// Test direction helper
	if fwDirectionToString(fwRuleDirectionIn) != "In" {
		t.Error("Expected 'In' for inbound direction")
	}
	if fwDirectionToString(fwRuleDirectionOut) != "Out" {
		t.Error("Expected 'Out' for outbound direction")
	}

	// Test protocol helper
	if fwProtocolToString(fwIPProtocolTCP) != "TCP" {
		t.Error("Expected 'TCP'")
	}
	if fwProtocolToString(fwIPProtocolUDP) != "UDP" {
		t.Error("Expected 'UDP'")
	}
	if fwProtocolToString(fwIPProtocolAny) != "Any" {
		t.Error("Expected 'Any'")
	}
	if fwProtocolToString(1) != "ICMPv4" {
		t.Error("Expected 'ICMPv4'")
	}

	// Test action helper
	if fwActionIntToString(fwActionAllow) != "Allow" {
		t.Error("Expected 'Allow'")
	}
	if fwActionIntToString(fwActionBlock) != "Block" {
		t.Error("Expected 'Block'")
	}

	// Test variantToInt with nil
	if variantToInt(nil) != 0 {
		t.Error("Expected 0 for nil variant")
	}
}

func TestFirewallConstants(t *testing.T) {
	// Verify COM constants match Windows definitions
	if fwIPProtocolTCP != 6 {
		t.Errorf("TCP protocol should be 6, got %d", fwIPProtocolTCP)
	}
	if fwIPProtocolUDP != 17 {
		t.Errorf("UDP protocol should be 17, got %d", fwIPProtocolUDP)
	}
	if fwRuleDirectionIn != 1 {
		t.Errorf("Inbound direction should be 1, got %d", fwRuleDirectionIn)
	}
	if fwRuleDirectionOut != 2 {
		t.Errorf("Outbound direction should be 2, got %d", fwRuleDirectionOut)
	}
	if fwActionBlock != 0 {
		t.Errorf("Block action should be 0, got %d", fwActionBlock)
	}
	if fwActionAllow != 1 {
		t.Errorf("Allow action should be 1, got %d", fwActionAllow)
	}
}
