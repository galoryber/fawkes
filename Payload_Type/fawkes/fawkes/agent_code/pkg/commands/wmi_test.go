//go:build windows
// +build windows

package commands

import (
	"encoding/json"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestWmiCommand_Name(t *testing.T) {
	cmd := &WmiCommand{}
	if cmd.Name() != "wmi" {
		t.Errorf("expected 'wmi', got '%s'", cmd.Name())
	}
}

func TestWmiCommand_Description(t *testing.T) {
	cmd := &WmiCommand{}
	if !strings.Contains(cmd.Description(), "COM API") {
		t.Errorf("description should mention COM API, got '%s'", cmd.Description())
	}
}

func TestWmiCommand_EmptyParams(t *testing.T) {
	cmd := &WmiCommand{}
	result := cmd.Execute(structs.Task{Params: ""})
	if result.Status != "error" {
		t.Error("expected error for empty params")
	}
	if !strings.Contains(result.Output, "parameters required") {
		t.Errorf("expected parameters required message, got '%s'", result.Output)
	}
}

func TestWmiCommand_InvalidJSON(t *testing.T) {
	cmd := &WmiCommand{}
	result := cmd.Execute(structs.Task{Params: "not json"})
	if result.Status != "error" {
		t.Error("expected error for invalid JSON")
	}
	if !strings.Contains(result.Output, "Error parsing") {
		t.Errorf("expected parsing error, got '%s'", result.Output)
	}
}

func TestWmiCommand_UnknownAction(t *testing.T) {
	cmd := &WmiCommand{}
	params, _ := json.Marshal(wmiArgs{Action: "invalid"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Error("expected error for unknown action")
	}
	if !strings.Contains(result.Output, "Unknown action") {
		t.Errorf("expected unknown action message, got '%s'", result.Output)
	}
}

func TestWmiCommand_ExecuteNoCommand(t *testing.T) {
	cmd := &WmiCommand{}
	params, _ := json.Marshal(wmiArgs{Action: "execute"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Error("expected error when command is empty")
	}
	if !strings.Contains(result.Output, "command parameter is required") {
		t.Errorf("expected command required message, got '%s'", result.Output)
	}
}

func TestWmiCommand_QueryNoQuery(t *testing.T) {
	cmd := &WmiCommand{}
	params, _ := json.Marshal(wmiArgs{Action: "query"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Error("expected error when query is empty")
	}
	if !strings.Contains(result.Output, "query parameter is required") {
		t.Errorf("expected query required message, got '%s'", result.Output)
	}
}

func TestWmiCommand_OsInfo(t *testing.T) {
	cmd := &WmiCommand{}
	params, _ := json.Marshal(wmiArgs{Action: "os-info"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Errorf("expected success for os-info, got '%s': %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "WMI OS Info") {
		t.Errorf("expected OS info header, got '%s'", result.Output)
	}
	// Should contain Windows version info
	if !strings.Contains(result.Output, "Caption") && !strings.Contains(result.Output, "Version") {
		t.Errorf("expected Caption or Version in output, got '%s'", result.Output)
	}
}

func TestWmiCommand_ProcessList(t *testing.T) {
	cmd := &WmiCommand{}
	params, _ := json.Marshal(wmiArgs{Action: "process-list"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Errorf("expected success for process-list, got '%s': %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "WMI Process List") {
		t.Errorf("expected process list header, got '%s'", result.Output)
	}
}

func TestWmiCommand_Query(t *testing.T) {
	cmd := &WmiCommand{}
	params, _ := json.Marshal(wmiArgs{
		Action: "query",
		Query:  "SELECT Caption, Version FROM Win32_OperatingSystem",
	})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Errorf("expected success for query, got '%s': %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "WMI Query Result") {
		t.Errorf("expected query result header, got '%s'", result.Output)
	}
}

func TestVariantToString_Nil(t *testing.T) {
	result := variantToString(nil)
	if result != "" {
		t.Errorf("expected empty string for nil variant, got '%s'", result)
	}
}
