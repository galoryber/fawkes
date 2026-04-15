package commands

import (
	"encoding/json"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestVSSShutdownRequiresConfirm(t *testing.T) {
	cmd := &VSSCommand{}
	params, _ := json.Marshal(map[string]interface{}{"action": "shutdown"})
	task := structs.Task{Params: string(params)}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Error("Expected error for shutdown without confirm")
	}
	if !strings.Contains(result.Output, "SAFETY") {
		t.Errorf("Expected safety message, got: %s", result.Output)
	}
	if !strings.Contains(result.Output, "confirm") {
		t.Errorf("Expected confirm instruction, got: %s", result.Output)
	}
	if !strings.Contains(result.Output, "T1529") {
		t.Errorf("Expected T1529 reference, got: %s", result.Output)
	}
}

func TestVSSShutdownWithConfirmFalse(t *testing.T) {
	cmd := &VSSCommand{}
	params, _ := json.Marshal(map[string]interface{}{"action": "shutdown", "confirm": false})
	task := structs.Task{Params: string(params)}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Error("Expected error for shutdown with confirm=false")
	}
}

func TestVSSRebootRequiresConfirm(t *testing.T) {
	cmd := &VSSCommand{}
	params, _ := json.Marshal(map[string]interface{}{"action": "reboot"})
	task := structs.Task{Params: string(params)}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Error("Expected error for reboot without confirm")
	}
	if !strings.Contains(result.Output, "SAFETY") {
		t.Errorf("Expected safety message, got: %s", result.Output)
	}
	if !strings.Contains(result.Output, "T1529") {
		t.Errorf("Expected T1529 reference, got: %s", result.Output)
	}
}

func TestVSSRebootWithConfirmFalse(t *testing.T) {
	cmd := &VSSCommand{}
	params, _ := json.Marshal(map[string]interface{}{"action": "reboot", "confirm": false})
	task := structs.Task{Params: string(params)}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Error("Expected error for reboot with confirm=false")
	}
}

func TestVSSShutdownRebootCrossPlatform(t *testing.T) {
	cmd := &VSSCommand{}
	if cmd.Name() != "vss" {
		t.Errorf("Expected name 'vss', got '%s'", cmd.Name())
	}
	if cmd.Description() == "" {
		t.Error("Description should not be empty")
	}
}
