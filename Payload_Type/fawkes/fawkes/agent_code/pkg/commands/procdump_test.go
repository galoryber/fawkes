//go:build windows

package commands

import (
	"encoding/json"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestProcdumpCommand_NameAndDescription(t *testing.T) {
	cmd := &ProcdumpCommand{}
	if cmd.Name() != "procdump" {
		t.Errorf("Name() = %q, want %q", cmd.Name(), "procdump")
	}
	if cmd.Description() == "" {
		t.Error("Description() should not be empty")
	}
	if !strings.Contains(cmd.Description(), "MiniDumpWriteDump") {
		t.Error("Description should mention MiniDumpWriteDump")
	}
}

func TestProcdumpCommand_InvalidJSON(t *testing.T) {
	cmd := &ProcdumpCommand{}
	result := cmd.Execute(structs.Task{Params: "not json"})
	if result.Status != "error" {
		t.Errorf("expected error for invalid JSON, got %q", result.Status)
	}
	if !result.Completed {
		t.Error("expected Completed=true")
	}
}

func TestProcdumpCommand_UnknownAction(t *testing.T) {
	cmd := &ProcdumpCommand{}
	params, _ := json.Marshal(procdumpArgs{Action: "badaction"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error for unknown action, got %q", result.Status)
	}
	if !strings.Contains(result.Output, "Unknown action") {
		t.Errorf("expected 'Unknown action' in output, got: %s", result.Output)
	}
}

func TestProcdumpCommand_DumpActionNoPID(t *testing.T) {
	cmd := &ProcdumpCommand{}
	params, _ := json.Marshal(procdumpArgs{Action: "dump", PID: 0})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error for dump action without PID, got %q", result.Status)
	}
	if !strings.Contains(result.Output, "-pid is required") {
		t.Errorf("expected '-pid is required' in output, got: %s", result.Output)
	}
}

func TestProcdumpArgs_JSONParsing(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantAct  string
		wantPID  int
	}{
		{"lsass action", `{"action":"lsass"}`, "lsass", 0},
		{"dump action", `{"action":"dump","pid":1234}`, "dump", 1234},
		{"empty JSON defaults", `{}`, "", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var args procdumpArgs
			err := json.Unmarshal([]byte(tt.input), &args)
			if err != nil {
				t.Fatalf("failed to parse JSON: %v", err)
			}
			if args.Action != tt.wantAct {
				t.Errorf("Action = %q, want %q", args.Action, tt.wantAct)
			}
			if args.PID != tt.wantPID {
				t.Errorf("PID = %d, want %d", args.PID, tt.wantPID)
			}
		})
	}
}

func TestProcdumpCommand_DefaultAction(t *testing.T) {
	// Empty params should default to "lsass" action
	cmd := &ProcdumpCommand{}
	result := cmd.Execute(structs.Task{Params: ""})
	// Should attempt lsass action — will fail on non-admin but shouldn't error as "unknown"
	if result.Status == "error" {
		if strings.Contains(result.Output, "Unknown action") {
			t.Error("empty params should default to lsass action, not unknown")
		}
	}
}

func TestProcdumpCommand_DumpInvalidPID(t *testing.T) {
	cmd := &ProcdumpCommand{}
	params, _ := json.Marshal(procdumpArgs{Action: "dump", PID: 999999})
	result := cmd.Execute(structs.Task{Params: string(params)})
	// PID 999999 almost certainly doesn't exist — should fail with OpenProcess error
	if result.Status != "error" {
		t.Logf("Unexpected success for PID 999999 — may be running as admin with valid PID collision")
	}
}

func TestFindProcessByName(t *testing.T) {
	// Try to find a well-known process
	pid, name, err := findProcessByName("explorer.exe")
	if err != nil {
		t.Logf("explorer.exe not found (expected in non-GUI environments): %v", err)
		return
	}
	if pid == 0 {
		t.Error("expected non-zero PID for explorer.exe")
	}
	if !strings.EqualFold(name, "explorer.exe") {
		t.Errorf("expected explorer.exe, got %q", name)
	}
}

func TestFindProcessByName_NotFound(t *testing.T) {
	_, _, err := findProcessByName("nonexistent_process_12345.exe")
	if err == nil {
		t.Error("expected error for non-existent process")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("expected 'not found' in error, got: %v", err)
	}
}

func TestGetProcessName(t *testing.T) {
	// PID 4 is always System on Windows
	name, err := getProcessName(4)
	if err != nil {
		t.Logf("Could not get process name for PID 4: %v", err)
		return
	}
	if !strings.EqualFold(name, "System") {
		t.Errorf("expected System for PID 4, got %q", name)
	}
}

func TestGetProcessName_NotFound(t *testing.T) {
	_, err := getProcessName(999999)
	if err == nil {
		t.Error("expected error for non-existent PID")
	}
}

func TestFormatDumpSize(t *testing.T) {
	tests := []struct {
		input    int64
		expected string
	}{
		{0, "0 bytes"},
		{512, "512 bytes"},
		{1024, "1.0 KB"},
		{1536, "1.5 KB"},
		{1048576, "1.0 MB"},
		{157286400, "150.0 MB"},
		{1073741824, "1.0 GB"},
	}
	for _, tt := range tests {
		result := formatDumpSize(tt.input)
		if result != tt.expected {
			t.Errorf("formatDumpSize(%d) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}
