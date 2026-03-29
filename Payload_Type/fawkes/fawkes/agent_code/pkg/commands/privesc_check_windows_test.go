//go:build windows
// +build windows

package commands

import (
	"encoding/json"
	"testing"

	"fawkes/pkg/structs"
)

func TestPrivescCheckCommand_Name(t *testing.T) {
	cmd := &PrivescCheckCommand{}
	if cmd.Name() != "privesc-check" {
		t.Errorf("expected 'privesc-check', got %q", cmd.Name())
	}
}

func TestPrivescCheckCommand_Description(t *testing.T) {
	cmd := &PrivescCheckCommand{}
	if cmd.Description() == "" {
		t.Error("description should not be empty")
	}
}

func TestPrivescCheckArgs_Actions(t *testing.T) {
	validActions := []string{"all", "privileges", "services", "registry", "writable", "unattend", "uac"}

	for _, action := range validActions {
		t.Run(action, func(t *testing.T) {
			var args privescCheckArgs
			data, _ := json.Marshal(privescCheckArgs{Action: action})
			if err := json.Unmarshal(data, &args); err != nil {
				t.Fatalf("unmarshal failed: %v", err)
			}
			if args.Action != action {
				t.Errorf("expected %q, got %q", action, args.Action)
			}
		})
	}
}

func TestPrivescCheckCommand_InvalidAction(t *testing.T) {
	cmd := &PrivescCheckCommand{}
	task := structs.Task{Params: `{"action":"nonexistent"}`}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Errorf("expected error for invalid action, got %q", result.Status)
	}
}

func TestPrivescCheckCommand_InvalidJSON(t *testing.T) {
	cmd := &PrivescCheckCommand{}
	task := structs.Task{Params: "{bad json"}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Errorf("expected error for invalid JSON, got %q", result.Status)
	}
}

func TestPrivescCheckCommand_EmptyDefaultsToAll(t *testing.T) {
	// With empty params, action should default to "all"
	cmd := &PrivescCheckCommand{}
	task := structs.Task{Params: ""}
	result := cmd.Execute(task)
	// The command will attempt to run privilege checks on the actual system
	// It should not return an error about "Unknown action"
	if result.Status == "error" && result.Output != "" {
		// If it errors, it should be a system error, not an action error
		if result.Output == "Unknown action:" {
			t.Error("empty params should default to 'all', not produce unknown action error")
		}
	}
	// Just verify it doesn't panic — actual checks require Windows context
}

func TestPrivescCheckCommand_CaseInsensitive(t *testing.T) {
	cmd := &PrivescCheckCommand{}
	tests := []string{
		`{"action":"ALL"}`,
		`{"action":"Privileges"}`,
		`{"action":"SERVICES"}`,
		`{"action":"Registry"}`,
	}
	for _, params := range tests {
		task := structs.Task{Params: params}
		result := cmd.Execute(task)
		// Should not return "Unknown action" error
		if result.Status == "error" && result.Output != "" {
			if len(result.Output) > 15 && result.Output[:15] == "Unknown action:" {
				t.Errorf("action should be case-insensitive, got error for %s", params)
			}
		}
	}
}

func TestReadRegDWORD_InvalidPath(t *testing.T) {
	// Reading a non-existent registry key should return 0 (default)
	val := readRegDWORD(0x80000002, `SOFTWARE\NonExistent\Key\Path`, "NonExistentValue")
	if val != 0 {
		t.Errorf("expected 0 for non-existent key, got %d", val)
	}
}

func TestReadRegString_InvalidPath(t *testing.T) {
	// Reading a non-existent registry key should return empty string
	val := readRegString(0x80000002, `SOFTWARE\NonExistent\Key\Path`, "NonExistentValue")
	if val != "" {
		t.Errorf("expected empty string for non-existent key, got %q", val)
	}
}
