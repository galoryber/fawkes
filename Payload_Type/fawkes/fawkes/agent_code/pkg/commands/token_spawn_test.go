//go:build windows
// +build windows

package commands

import (
	"encoding/json"
	"testing"

	"fawkes/pkg/structs"
)

func TestStealToken_ActionParsing(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		wantAction string
		wantPID    int
		wantCmd    string
	}{
		{
			"default action (empty)",
			`{"pid":1234}`,
			"", 1234, "",
		},
		{
			"explicit impersonate",
			`{"pid":1234,"action":"impersonate"}`,
			"impersonate", 1234, "",
		},
		{
			"spawn action",
			`{"pid":1234,"action":"spawn","command":"cmd.exe /c whoami"}`,
			"spawn", 1234, "cmd.exe /c whoami",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var params StealTokenParams
			if err := json.Unmarshal([]byte(tt.input), &params); err != nil {
				t.Fatalf("JSON unmarshal failed: %v", err)
			}
			if params.Action != tt.wantAction {
				t.Errorf("Action = %q, want %q", params.Action, tt.wantAction)
			}
			if params.PID != tt.wantPID {
				t.Errorf("PID = %d, want %d", params.PID, tt.wantPID)
			}
			if params.Command != tt.wantCmd {
				t.Errorf("Command = %q, want %q", params.Command, tt.wantCmd)
			}
		})
	}
}

func TestStealToken_SpawnRequiresCommand(t *testing.T) {
	cmd := &StealTokenCommand{}
	result := cmd.Execute(structs.Task{Params: `{"pid":1234,"action":"spawn"}`})
	if result.Status != "error" {
		t.Errorf("spawn without command should error, got status=%q", result.Status)
	}
	if result.Output != "command parameter is required for spawn action" {
		t.Errorf("Output = %q, want command required error", result.Output)
	}
}

func TestStealToken_SpawnEmptyCommand(t *testing.T) {
	cmd := &StealTokenCommand{}
	result := cmd.Execute(structs.Task{Params: `{"pid":1234,"action":"spawn","command":""}`})
	if result.Status != "error" {
		t.Errorf("spawn with empty command should error, got status=%q", result.Status)
	}
}

func TestStealToken_UnknownAction(t *testing.T) {
	cmd := &StealTokenCommand{}
	result := cmd.Execute(structs.Task{Params: `{"pid":1234,"action":"badaction"}`})
	if result.Status != "error" {
		t.Errorf("unknown action should error, got status=%q", result.Status)
	}
}

func TestMakeToken_ActionParsing(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		wantAction string
		wantCmd    string
	}{
		{
			"default action (empty)",
			`{"username":"user","password":"pw"}`,
			"", "",
		},
		{
			"explicit impersonate",
			`{"username":"user","password":"pw","action":"impersonate"}`,
			"impersonate", "",
		},
		{
			"spawn action",
			`{"username":"admin","password":"P@ss","domain":"CORP","action":"spawn","command":"notepad.exe"}`,
			"spawn", "notepad.exe",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var params MakeTokenParams
			if err := json.Unmarshal([]byte(tt.input), &params); err != nil {
				t.Fatalf("JSON unmarshal failed: %v", err)
			}
			if params.Action != tt.wantAction {
				t.Errorf("Action = %q, want %q", params.Action, tt.wantAction)
			}
			if params.Command != tt.wantCmd {
				t.Errorf("Command = %q, want %q", params.Command, tt.wantCmd)
			}
		})
	}
}

func TestMakeToken_SpawnRequiresCommand(t *testing.T) {
	cmd := &MakeTokenCommand{}
	result := cmd.Execute(structs.Task{Params: `{"username":"user","password":"pw","action":"spawn"}`})
	if result.Status != "error" {
		t.Errorf("spawn without command should error, got status=%q", result.Status)
	}
	if result.Output != "command parameter is required for spawn action" {
		t.Errorf("Output = %q, want command required error", result.Output)
	}
}

func TestMakeToken_SpawnEmptyCommand(t *testing.T) {
	cmd := &MakeTokenCommand{}
	result := cmd.Execute(structs.Task{Params: `{"username":"user","password":"pw","action":"spawn","command":""}`})
	if result.Status != "error" {
		t.Errorf("spawn with empty command should error, got status=%q", result.Status)
	}
}

func TestMakeToken_UnknownAction(t *testing.T) {
	cmd := &MakeTokenCommand{}
	result := cmd.Execute(structs.Task{Params: `{"username":"user","password":"pw","action":"badaction"}`})
	if result.Status != "error" {
		t.Errorf("unknown action should error, got status=%q", result.Status)
	}
}

func TestSpawnResult_Struct(t *testing.T) {
	// Verify SpawnResult struct fields
	result := &SpawnResult{
		PID:      12345,
		Identity: "CORP\\admin",
	}
	if result.PID != 12345 {
		t.Errorf("PID = %d, want 12345", result.PID)
	}
	if result.Identity != "CORP\\admin" {
		t.Errorf("Identity = %q, want %q", result.Identity, "CORP\\admin")
	}
}
