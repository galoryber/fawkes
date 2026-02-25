//go:build windows
// +build windows

package commands

import (
	"encoding/json"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestPsExecNameAndDescription(t *testing.T) {
	cmd := &PsExecCommand{}
	if cmd.Name() != "psexec" {
		t.Errorf("Expected name 'psexec', got '%s'", cmd.Name())
	}
	if cmd.Description() == "" {
		t.Error("Description should not be empty")
	}
}

func TestPsExecEmptyParams(t *testing.T) {
	cmd := &PsExecCommand{}
	task := structs.Task{Params: ""}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Error("Expected error for empty params")
	}
	if !strings.Contains(result.Output, "parameters required") {
		t.Errorf("Expected parameters required error, got: %s", result.Output)
	}
}

func TestPsExecInvalidJSON(t *testing.T) {
	cmd := &PsExecCommand{}
	task := structs.Task{Params: "not json"}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Error("Expected error for invalid JSON")
	}
	if !strings.Contains(result.Output, "Error parsing parameters") {
		t.Errorf("Expected parsing error, got: %s", result.Output)
	}
}

func TestPsExecMissingHost(t *testing.T) {
	cmd := &PsExecCommand{}
	params, _ := json.Marshal(map[string]string{"command": "whoami"})
	task := structs.Task{Params: string(params)}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Error("Expected error for missing host")
	}
	if !strings.Contains(result.Output, "host is required") {
		t.Errorf("Expected host required error, got: %s", result.Output)
	}
}

func TestPsExecMissingCommand(t *testing.T) {
	cmd := &PsExecCommand{}
	params, _ := json.Marshal(map[string]string{"host": "target"})
	task := structs.Task{Params: string(params)}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Error("Expected error for missing command")
	}
	if !strings.Contains(result.Output, "command is required") {
		t.Errorf("Expected command required error, got: %s", result.Output)
	}
}

func TestPsExecInvalidHost(t *testing.T) {
	cmd := &PsExecCommand{}
	params, _ := json.Marshal(map[string]string{
		"host":    "nonexistent-host-12345",
		"command": "whoami",
	})
	task := structs.Task{Params: string(params)}
	result := cmd.Execute(task)
	// Should fail to connect to remote SCM
	if result.Status != "error" {
		t.Error("Expected error for invalid host")
	}
	if !strings.Contains(result.Output, "Error") || !strings.Contains(result.Output, "SCM") {
		t.Errorf("Expected SCM connection error, got: %s", result.Output)
	}
}

func TestPsExecRandomServiceName(t *testing.T) {
	names := make(map[string]bool)
	for i := 0; i < 10; i++ {
		name := randomServiceName()
		if name == "" {
			t.Error("Random service name should not be empty")
		}
		if len(name) < 6 {
			t.Errorf("Service name too short: %s", name)
		}
		names[name] = true
	}
	// With 10 random names, there should be at least some variety
	if len(names) < 5 {
		t.Error("Random service names are not sufficiently random")
	}
}

func TestPsExecCleanupFlag(t *testing.T) {
	// We can't test full execution without a remote host, but we can
	// verify the command processes cleanup parameter correctly by
	// checking with a nonexistent host — it will fail at SCM connect
	cmd := &PsExecCommand{}

	// Default cleanup (true)
	params, _ := json.Marshal(map[string]string{
		"host":    "nonexistent-host",
		"command": "whoami",
	})
	task := structs.Task{Params: string(params)}
	result := cmd.Execute(task)
	if !strings.Contains(result.Output, "Cleanup:  true") {
		t.Errorf("Expected cleanup true, got: %s", result.Output)
	}

	// Explicit cleanup=false
	params, _ = json.Marshal(map[string]string{
		"host":    "nonexistent-host",
		"command": "whoami",
		"cleanup": "false",
	})
	task = structs.Task{Params: string(params)}
	result = cmd.Execute(task)
	if !strings.Contains(result.Output, "Cleanup:  false") {
		t.Errorf("Expected cleanup false, got: %s", result.Output)
	}
}

func TestPsExecCommandWrapping(t *testing.T) {
	cmd := &PsExecCommand{}

	// Plain command should get cmd.exe /c prefix
	params, _ := json.Marshal(map[string]string{
		"host":    "nonexistent-host",
		"command": "whoami",
	})
	task := structs.Task{Params: string(params)}
	result := cmd.Execute(task)
	if !strings.Contains(result.Output, `cmd.exe /c whoami`) {
		t.Errorf("Expected cmd.exe wrapper, got: %s", result.Output)
	}

	// cmd.exe prefix should not be double-wrapped
	params, _ = json.Marshal(map[string]string{
		"host":    "nonexistent-host",
		"command": "cmd.exe /c whoami",
	})
	task = structs.Task{Params: string(params)}
	result = cmd.Execute(task)
	if strings.Count(result.Output, "cmd.exe") > 1 {
		t.Errorf("Should not double-wrap cmd.exe prefix, got: %s", result.Output)
	}
}

func TestPsExecCustomServiceName(t *testing.T) {
	cmd := &PsExecCommand{}
	params, _ := json.Marshal(map[string]string{
		"host":    "nonexistent-host",
		"command": "whoami",
		"name":    "MyCustomSvc",
		"display": "My Custom Service",
	})
	task := structs.Task{Params: string(params)}
	result := cmd.Execute(task)
	if !strings.Contains(result.Output, "MyCustomSvc") {
		t.Errorf("Expected custom service name, got: %s", result.Output)
	}
}
