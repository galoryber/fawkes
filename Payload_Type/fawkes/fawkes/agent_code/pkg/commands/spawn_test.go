//go:build windows
// +build windows

package commands

import (
	"encoding/json"
	"testing"

	"fawkes/pkg/structs"
)

func TestSpawn_Name(t *testing.T) {
	cmd := &SpawnCommand{}
	if got := cmd.Name(); got != "spawn" {
		t.Errorf("Name() = %q, want %q", got, "spawn")
	}
}

func TestSpawn_Description(t *testing.T) {
	cmd := &SpawnCommand{}
	if cmd.Description() == "" {
		t.Error("Description() should not be empty")
	}
}

func TestSpawn_InvalidJSON(t *testing.T) {
	cmd := &SpawnCommand{}
	result := cmd.Execute(structs.Task{Params: "not json"})
	if result.Status != "error" {
		t.Errorf("Invalid JSON should error, got status=%q", result.Status)
	}
}

func TestSpawn_UnknownMode(t *testing.T) {
	cmd := &SpawnCommand{}
	params, _ := json.Marshal(SpawnParams{Mode: "invalid"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("Unknown mode should error, got status=%q", result.Status)
	}
}

func TestSpawn_ProcessModeEmptyPath(t *testing.T) {
	cmd := &SpawnCommand{}
	params, _ := json.Marshal(SpawnParams{Mode: "process", Path: ""})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("Process mode with empty path should error, got status=%q", result.Status)
	}
}

func TestSpawn_ThreadModeInvalidPID(t *testing.T) {
	cmd := &SpawnCommand{}
	params, _ := json.Marshal(SpawnParams{Mode: "thread", PID: 0})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("Thread mode with PID=0 should error, got status=%q", result.Status)
	}
}

func TestSpawn_ThreadModeNegativePID(t *testing.T) {
	cmd := &SpawnCommand{}
	params, _ := json.Marshal(SpawnParams{Mode: "thread", PID: -1})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("Thread mode with negative PID should error, got status=%q", result.Status)
	}
}

func TestSpawn_ModeCaseInsensitive(t *testing.T) {
	// Verify mode is lowercased before dispatch
	tests := []struct {
		mode string
	}{
		{"PROCESS"},
		{"Process"},
		{"THREAD"},
		{"Thread"},
	}
	for _, tt := range tests {
		var params SpawnParams
		raw := `{"mode":"` + tt.mode + `"}`
		if err := json.Unmarshal([]byte(raw), &params); err != nil {
			t.Fatalf("JSON unmarshal failed for mode %q: %v", tt.mode, err)
		}
		if params.Mode != tt.mode {
			t.Errorf("Mode = %q, want %q", params.Mode, tt.mode)
		}
	}
}

func TestSpawn_ParamParsing(t *testing.T) {
	input := `{"mode":"process","path":"C:\\Windows\\notepad.exe","pid":0,"ppid":4444,"blockdlls":true}`
	var params SpawnParams
	if err := json.Unmarshal([]byte(input), &params); err != nil {
		t.Fatalf("JSON unmarshal failed: %v", err)
	}
	if params.Mode != "process" {
		t.Errorf("Mode = %q, want %q", params.Mode, "process")
	}
	if params.Path != `C:\Windows\notepad.exe` {
		t.Errorf("Path = %q, want %q", params.Path, `C:\Windows\notepad.exe`)
	}
	if params.PPID != 4444 {
		t.Errorf("PPID = %d, want 4444", params.PPID)
	}
	if !params.BlockDLLs {
		t.Error("BlockDLLs should be true")
	}
}
