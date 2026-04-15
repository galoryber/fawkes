//go:build linux

package commands

import (
	"encoding/json"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestSpawnLinux_Name(t *testing.T) {
	cmd := &SpawnCommand{}
	if cmd.Name() != "spawn" {
		t.Errorf("expected 'spawn', got '%s'", cmd.Name())
	}
}

func TestSpawnLinux_ProcessMode(t *testing.T) {
	cmd := &SpawnCommand{}
	params, _ := json.Marshal(SpawnParams{Mode: "process", Path: "/bin/sleep 3600"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Errorf("expected success, got %s: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "PID") {
		t.Error("output should contain PID")
	}
	if !strings.Contains(result.Output, "PTRACE_TRACEME") {
		t.Error("output should mention PTRACE_TRACEME")
	}
}

func TestSpawnLinux_EmptyPath(t *testing.T) {
	cmd := &SpawnCommand{}
	params, _ := json.Marshal(SpawnParams{Mode: "process", Path: ""})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error for empty path, got %s", result.Status)
	}
}

func TestSpawnLinux_ThreadMode(t *testing.T) {
	cmd := &SpawnCommand{}
	params, _ := json.Marshal(SpawnParams{Mode: "thread", PID: 1})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error for thread mode on Linux, got %s", result.Status)
	}
}

func TestSpawnLinux_InvalidMode(t *testing.T) {
	cmd := &SpawnCommand{}
	params, _ := json.Marshal(SpawnParams{Mode: "unknown", Path: "/bin/sleep"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error for unknown mode, got %s", result.Status)
	}
}

func TestSpawnLinux_DefaultMode(t *testing.T) {
	cmd := &SpawnCommand{}
	params, _ := json.Marshal(SpawnParams{Path: "/bin/sleep 3600"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Errorf("expected success with default mode, got %s: %s", result.Status, result.Output)
	}
}

func TestSpawnLinux_InvalidBinary(t *testing.T) {
	cmd := &SpawnCommand{}
	params, _ := json.Marshal(SpawnParams{Mode: "process", Path: "/nonexistent/binary"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error for invalid binary, got %s", result.Status)
	}
}

func TestArgueLinux_Name(t *testing.T) {
	cmd := &ArgueCommand{}
	if cmd.Name() != "argue" {
		t.Errorf("expected 'argue', got '%s'", cmd.Name())
	}
}

func TestArgueLinux_EmptyCommand(t *testing.T) {
	cmd := &ArgueCommand{}
	params, _ := json.Marshal(argueParams{Command: "", Spoof: "/bin/notepad"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error for empty command, got %s", result.Status)
	}
}

func TestArgueLinux_EmptySpoof(t *testing.T) {
	cmd := &ArgueCommand{}
	params, _ := json.Marshal(argueParams{Command: "/bin/echo hello", Spoof: ""})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error for empty spoof, got %s", result.Status)
	}
}

func TestArgueLinux_ParamParsing(t *testing.T) {
	args := argueParams{Command: "real", Spoof: "fake"}
	if args.Command != "real" || args.Spoof != "fake" {
		t.Error("param struct field mismatch")
	}
}
