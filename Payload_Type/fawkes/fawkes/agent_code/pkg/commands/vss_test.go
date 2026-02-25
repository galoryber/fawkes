//go:build windows
// +build windows

package commands

import (
	"encoding/json"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestVSSNameAndDescription(t *testing.T) {
	cmd := &VSSCommand{}
	if cmd.Name() != "vss" {
		t.Errorf("Expected name 'vss', got '%s'", cmd.Name())
	}
	if cmd.Description() == "" {
		t.Error("Description should not be empty")
	}
}

func TestVSSInvalidJSON(t *testing.T) {
	cmd := &VSSCommand{}
	task := structs.Task{Params: "not json"}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Error("Expected error status for invalid JSON")
	}
	if !strings.Contains(result.Output, "Error parsing parameters") {
		t.Errorf("Expected parsing error, got: %s", result.Output)
	}
}

func TestVSSEmptyParams(t *testing.T) {
	cmd := &VSSCommand{}
	task := structs.Task{Params: ""}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Error("Expected error for empty params")
	}
	if !strings.Contains(result.Output, "parameters required") {
		t.Errorf("Expected parameters required error, got: %s", result.Output)
	}
}

func TestVSSUnknownAction(t *testing.T) {
	cmd := &VSSCommand{}
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

func TestVSSDeleteMissingID(t *testing.T) {
	cmd := &VSSCommand{}
	params, _ := json.Marshal(map[string]string{"action": "delete"})
	task := structs.Task{Params: string(params)}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Error("Expected error for delete without id")
	}
	if !strings.Contains(result.Output, "id is required") {
		t.Errorf("Expected id required error, got: %s", result.Output)
	}
}

func TestVSSExtractMissingParams(t *testing.T) {
	cmd := &VSSCommand{}

	// Missing id
	params, _ := json.Marshal(map[string]string{"action": "extract", "source": "test", "dest": "test"})
	task := structs.Task{Params: string(params)}
	result := cmd.Execute(task)
	if result.Status != "error" || !strings.Contains(result.Output, "id is required") {
		t.Errorf("Expected id required error, got: %s", result.Output)
	}

	// Missing source
	params, _ = json.Marshal(map[string]string{"action": "extract", "id": "test", "dest": "test"})
	task = structs.Task{Params: string(params)}
	result = cmd.Execute(task)
	if result.Status != "error" || !strings.Contains(result.Output, "source is required") {
		t.Errorf("Expected source required error, got: %s", result.Output)
	}

	// Missing dest
	params, _ = json.Marshal(map[string]string{"action": "extract", "id": "test", "source": "test"})
	task = structs.Task{Params: string(params)}
	result = cmd.Execute(task)
	if result.Status != "error" || !strings.Contains(result.Output, "dest is required") {
		t.Errorf("Expected dest required error, got: %s", result.Output)
	}
}

func TestVSSActionNormalization(t *testing.T) {
	cmd := &VSSCommand{}
	params, _ := json.Marshal(map[string]string{"action": "LIST"})
	task := structs.Task{Params: string(params)}
	result := cmd.Execute(task)
	// Should not fail with "Unknown action" — the actual WMI call may fail
	if strings.Contains(result.Output, "Unknown action") {
		t.Error("Action should be case-insensitive")
	}
}
