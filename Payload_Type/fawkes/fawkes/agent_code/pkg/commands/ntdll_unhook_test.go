//go:build windows
// +build windows

package commands

import (
	"encoding/json"
	"strings"
	"testing"
	"unsafe"

	"fawkes/pkg/structs"
)

func TestNtdllUnhookNameAndDescription(t *testing.T) {
	cmd := &NtdllUnhookCommand{}
	if cmd.Name() != "ntdll-unhook" {
		t.Errorf("Expected name 'ntdll-unhook', got '%s'", cmd.Name())
	}
	if cmd.Description() == "" {
		t.Error("Description should not be empty")
	}
}

func TestNtdllUnhookInvalidJSON(t *testing.T) {
	cmd := &NtdllUnhookCommand{}
	task := structs.Task{Params: "not json"}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Error("Expected error status for invalid JSON")
	}
	if !strings.Contains(result.Output, "Error parsing parameters") {
		t.Errorf("Expected parsing error, got: %s", result.Output)
	}
}

func TestNtdllUnhookUnknownAction(t *testing.T) {
	cmd := &NtdllUnhookCommand{}
	params, _ := json.Marshal(map[string]string{"action": "nonexistent"})
	task := structs.Task{Params: string(params)}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Error("Expected error status for unknown action")
	}
	if !strings.Contains(result.Output, "Unknown action") {
		t.Errorf("Expected unknown action error, got: %s", result.Output)
	}
}

func TestNtdllUnhookEmptyParams(t *testing.T) {
	cmd := &NtdllUnhookCommand{}
	task := structs.Task{Params: ""}
	result := cmd.Execute(task)
	// Should not fail on empty params (defaults to "unhook")
	if strings.Contains(result.Output, "Error parsing parameters") {
		t.Error("Should handle empty params gracefully")
	}
}

func TestNtdllUnhookDefaultAction(t *testing.T) {
	cmd := &NtdllUnhookCommand{}
	params, _ := json.Marshal(map[string]string{})
	task := structs.Task{Params: string(params)}
	result := cmd.Execute(task)
	// Default action is "unhook" — should attempt unhooking, not fail with "unknown action"
	if strings.Contains(result.Output, "Unknown action") {
		t.Error("Default action should be valid")
	}
}

func TestImageDOSHeaderSize(t *testing.T) {
	// IMAGE_DOS_HEADER should be 64 bytes
	var h imageDOSHeader
	size := unsafe.Sizeof(h)
	if size != 64 {
		t.Errorf("Expected imageDOSHeader size 64, got %d", size)
	}
}

func TestImageFileHeaderSize(t *testing.T) {
	// IMAGE_FILE_HEADER should be 20 bytes
	var h imageFileHeader
	size := unsafe.Sizeof(h)
	if size != 20 {
		t.Errorf("Expected imageFileHeader size 20, got %d", size)
	}
}

func TestImageSectionHeaderSize(t *testing.T) {
	// IMAGE_SECTION_HEADER should be 40 bytes
	var h imageSectionHeader
	size := unsafe.Sizeof(h)
	if size != 40 {
		t.Errorf("Expected imageSectionHeader size 40, got %d", size)
	}
}

func TestMinFunction(t *testing.T) {
	if min(5, 10) != 5 {
		t.Error("min(5, 10) should be 5")
	}
	if min(10, 5) != 5 {
		t.Error("min(10, 5) should be 5")
	}
	if min(5, 5) != 5 {
		t.Error("min(5, 5) should be 5")
	}
}

func TestNtdllUnhookActionNormalization(t *testing.T) {
	cmd := &NtdllUnhookCommand{}
	// Test uppercase action
	params, _ := json.Marshal(map[string]string{"action": "CHECK"})
	task := structs.Task{Params: string(params)}
	result := cmd.Execute(task)
	// Should not fail with "Unknown action" (case normalization)
	if strings.Contains(result.Output, "Unknown action") {
		t.Error("Action should be case-insensitive")
	}
}
