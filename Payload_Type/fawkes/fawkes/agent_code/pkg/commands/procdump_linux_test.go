//go:build linux

package commands

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestGetLinuxProcessNameSelf(t *testing.T) {
	pid := os.Getpid()
	name := getLinuxProcessName(pid)
	if name == "" {
		t.Error("expected non-empty process name for self")
	}
	// Our test process should have a recognizable name
	if strings.HasPrefix(name, "PID_") {
		t.Errorf("expected real process name, got fallback %q", name)
	}
}

func TestGetLinuxProcessNameInvalid(t *testing.T) {
	name := getLinuxProcessName(9999999)
	if !strings.HasPrefix(name, "PID_") {
		t.Errorf("expected fallback name for invalid PID, got %q", name)
	}
}

func TestGetLinuxProcessNamePID1(t *testing.T) {
	name := getLinuxProcessName(1)
	// PID 1 should always exist on Linux
	if name == "" {
		t.Error("expected non-empty name for PID 1")
	}
	if strings.HasPrefix(name, "PID_") {
		t.Log("Could not read PID 1 name (permission denied in container?)")
	}
}

func TestGetLinuxProcessOwnerSelf(t *testing.T) {
	pid := os.Getpid()
	owner := getLinuxProcessOwner(pid)
	if owner == "unknown" {
		t.Error("expected known owner for self")
	}
	if !strings.HasPrefix(owner, "uid=") {
		t.Errorf("expected uid=N format, got %q", owner)
	}
}

func TestGetLinuxProcessOwnerInvalid(t *testing.T) {
	owner := getLinuxProcessOwner(9999999)
	if owner != "unknown" {
		t.Errorf("expected 'unknown' for invalid PID, got %q", owner)
	}
}

func TestProcdumpLinuxExecuteInvalidJSON(t *testing.T) {
	cmd := &ProcdumpCommand{}
	result := cmd.Execute(structs.Task{Params: "not json"})
	if result.Status != "error" {
		t.Errorf("expected error for invalid JSON, got %q", result.Status)
	}
}

func TestProcdumpLinuxUnknownAction(t *testing.T) {
	cmd := &ProcdumpCommand{}
	params, _ := json.Marshal(procdumpArgs{Action: "badaction"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error for unknown action, got %q", result.Status)
	}
}

func TestProcdumpLinuxDumpNoPID(t *testing.T) {
	cmd := &ProcdumpCommand{}
	params, _ := json.Marshal(procdumpArgs{Action: "dump", PID: 0})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error for dump without PID, got %q", result.Status)
	}
	if !strings.Contains(result.Output, "-pid is required") {
		t.Errorf("expected '-pid is required' message, got %q", result.Output)
	}
}

func TestProcdumpLinuxDumpInvalidPID(t *testing.T) {
	cmd := &ProcdumpCommand{}
	params, _ := json.Marshal(procdumpArgs{Action: "dump", PID: 9999999})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error for non-existent PID, got %q", result.Status)
	}
}

func TestProcdumpLinuxLsassAction(t *testing.T) {
	cmd := &ProcdumpCommand{}
	params, _ := json.Marshal(procdumpArgs{Action: "lsass"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	// lsass action should return Windows-only error on Linux
	if result.Status != "error" {
		t.Errorf("expected error for lsass on Linux, got %q", result.Status)
	}
	if !strings.Contains(result.Output, "Windows") {
		t.Errorf("expected Windows-only message, got %q", result.Output)
	}
}

func TestProcdumpLinuxSearch(t *testing.T) {
	cmd := &ProcdumpCommand{}
	params, _ := json.Marshal(procdumpArgs{Action: "search"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	// Search should succeed on Linux (may or may not find credential processes)
	if result.Status != "success" {
		t.Errorf("expected success for search action, got %q: %s", result.Status, result.Output)
	}
}
