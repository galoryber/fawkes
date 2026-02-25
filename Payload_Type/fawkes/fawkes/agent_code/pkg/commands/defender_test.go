//go:build windows
// +build windows

package commands

import (
	"encoding/json"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestDefenderNameAndDescription(t *testing.T) {
	cmd := &DefenderCommand{}
	if cmd.Name() != "defender" {
		t.Errorf("Expected name 'defender', got '%s'", cmd.Name())
	}
	if cmd.Description() == "" {
		t.Error("Description should not be empty")
	}
}

func TestDefenderInvalidJSON(t *testing.T) {
	cmd := &DefenderCommand{}
	task := structs.Task{Params: "not json"}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Error("Expected error status for invalid JSON")
	}
	if !strings.Contains(result.Output, "Error parsing parameters") {
		t.Errorf("Expected parsing error, got: %s", result.Output)
	}
}

func TestDefenderEmptyParams(t *testing.T) {
	cmd := &DefenderCommand{}
	task := structs.Task{Params: ""}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Error("Expected error for empty params")
	}
	if !strings.Contains(result.Output, "parameters required") {
		t.Errorf("Expected parameters required error, got: %s", result.Output)
	}
}

func TestDefenderUnknownAction(t *testing.T) {
	cmd := &DefenderCommand{}
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

func TestDefenderAddExclusionMissingValue(t *testing.T) {
	cmd := &DefenderCommand{}
	params, _ := json.Marshal(map[string]string{"action": "add-exclusion"})
	task := structs.Task{Params: string(params)}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Error("Expected error for add-exclusion without value")
	}
	if !strings.Contains(result.Output, "value is required") {
		t.Errorf("Expected value required error, got: %s", result.Output)
	}
}

func TestDefenderRemoveExclusionMissingValue(t *testing.T) {
	cmd := &DefenderCommand{}
	params, _ := json.Marshal(map[string]string{"action": "remove-exclusion"})
	task := structs.Task{Params: string(params)}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Error("Expected error for remove-exclusion without value")
	}
	if !strings.Contains(result.Output, "value is required") {
		t.Errorf("Expected value required error, got: %s", result.Output)
	}
}

func TestDefenderAddExclusionInvalidType(t *testing.T) {
	cmd := &DefenderCommand{}
	params, _ := json.Marshal(map[string]string{"action": "add-exclusion", "type": "invalid", "value": "test"})
	task := structs.Task{Params: string(params)}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Error("Expected error for invalid exclusion type")
	}
	if !strings.Contains(result.Output, "Unknown exclusion type") {
		t.Errorf("Expected unknown type error, got: %s", result.Output)
	}
}

func TestDefenderActionNormalization(t *testing.T) {
	cmd := &DefenderCommand{}
	// Uppercase action should not fail with "Unknown action"
	params, _ := json.Marshal(map[string]string{"action": "STATUS"})
	task := structs.Task{Params: string(params)}
	result := cmd.Execute(task)
	if strings.Contains(result.Output, "Unknown action") {
		t.Error("Action should be case-insensitive")
	}
}

func TestDefenderExclusionTypeDefault(t *testing.T) {
	cmd := &DefenderCommand{}
	// Missing type should default to "path" not error
	params, _ := json.Marshal(map[string]string{"action": "add-exclusion", "value": "C:\\test"})
	task := structs.Task{Params: string(params)}
	result := cmd.Execute(task)
	// Should not error with "Unknown exclusion type"
	if strings.Contains(result.Output, "Unknown exclusion type") {
		t.Error("Should default to 'path' type")
	}
}
