//go:build darwin

package commands

import (
	"encoding/json"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestFirewallDarwinNameAndDescription(t *testing.T) {
	cmd := &FirewallCommand{}
	if cmd.Name() != "firewall" {
		t.Errorf("Expected name 'firewall', got '%s'", cmd.Name())
	}
	if cmd.Description() == "" {
		t.Error("Description should not be empty")
	}
}

func TestFirewallDarwinEmptyParams(t *testing.T) {
	cmd := &FirewallCommand{}
	task := structs.Task{Params: ""}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Error("Expected error for empty params")
	}
}

func TestFirewallDarwinInvalidJSON(t *testing.T) {
	cmd := &FirewallCommand{}
	task := structs.Task{Params: "not json"}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Error("Expected error for invalid JSON")
	}
}

func TestFirewallDarwinUnknownAction(t *testing.T) {
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

func TestFirewallDarwinStatusAction(t *testing.T) {
	cmd := &FirewallCommand{}
	params, _ := json.Marshal(map[string]string{"action": "status"})
	task := structs.Task{Params: string(params)}
	result := cmd.Execute(task)
	// Should succeed (even without root — just reports what it can)
	if result.Status != "success" {
		t.Errorf("Expected success, got %s: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "macOS Firewall Status") {
		t.Error("Expected status header in output")
	}
}

func TestFirewallDarwinListAction(t *testing.T) {
	cmd := &FirewallCommand{}
	params, _ := json.Marshal(map[string]string{"action": "list"})
	task := structs.Task{Params: string(params)}
	result := cmd.Execute(task)
	if result.Status != "success" {
		t.Errorf("Expected success, got %s: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "macOS Firewall Rules") {
		t.Error("Expected rules header in output")
	}
}

func TestFirewallDarwinAddMissingProgram(t *testing.T) {
	cmd := &FirewallCommand{}
	params, _ := json.Marshal(map[string]string{"action": "add"})
	task := structs.Task{Params: string(params)}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Error("Expected error for add without program")
	}
	if !strings.Contains(result.Output, "program path is required") {
		t.Errorf("Expected program required error, got: %s", result.Output)
	}
}

func TestFirewallDarwinDeleteMissingProgram(t *testing.T) {
	cmd := &FirewallCommand{}
	params, _ := json.Marshal(map[string]string{"action": "delete"})
	task := structs.Task{Params: string(params)}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Error("Expected error for delete without program")
	}
	if !strings.Contains(result.Output, "program path is required") {
		t.Errorf("Expected program required error, got: %s", result.Output)
	}
}

func TestFirewallDarwinActionCaseInsensitive(t *testing.T) {
	cmd := &FirewallCommand{}
	params, _ := json.Marshal(map[string]string{"action": "STATUS"})
	task := structs.Task{Params: string(params)}
	result := cmd.Execute(task)
	if strings.Contains(result.Output, "Unknown action") {
		t.Error("Action should be case-insensitive")
	}
}
