//go:build windows

package commands

import (
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestWinPrivescCheckServices_Output(t *testing.T) {
	result := winPrivescCheckServices()
	if result.Status != "success" {
		// May fail if we can't connect to SCM (non-admin)
		if strings.Contains(result.Output, "Failed to connect to SCM") {
			t.Skip("Cannot connect to SCM — need elevated permissions")
		}
		t.Errorf("expected success, got %q: %s", result.Status, result.Output)
	}

	// Should contain service check sections
	if !strings.Contains(result.Output, "Checked") {
		t.Error("expected service count in output")
	}
	if !strings.Contains(result.Output, "Unquoted service paths") {
		t.Error("expected unquoted paths section in output")
	}
	if !strings.Contains(result.Output, "Modifiable service binaries") {
		t.Error("expected modifiable binaries section in output")
	}
}

func TestWinPrivescCheckServiceRegistryPerms_Output(t *testing.T) {
	result := winPrivescCheckServiceRegistryPerms()
	if result.Status != "success" {
		if strings.Contains(result.Output, "Failed to open Services registry key") {
			t.Skip("Cannot open services registry — need elevated permissions")
		}
		t.Errorf("expected success, got %q: %s", result.Status, result.Output)
	}

	// Should contain registry check info
	if !strings.Contains(result.Output, "Checked") && !strings.Contains(result.Output, "service registry") {
		t.Error("expected service registry check info in output")
	}
}

func TestWinPrivescCheckWritable_Output(t *testing.T) {
	result := winPrivescCheckWritable()
	if result.Status != "success" {
		t.Errorf("expected success, got %q: %s", result.Status, result.Output)
	}

	// Should contain PATH directory analysis
	if !strings.Contains(result.Output, "Writable PATH directories") {
		t.Error("expected writable PATH directories section in output")
	}
}

func TestPrivescCheckCommand_ServiceActions(t *testing.T) {
	cmd := &PrivescCheckCommand{}
	actions := []string{"services", "writable", "service-registry"}

	for _, action := range actions {
		t.Run(action, func(t *testing.T) {
			task := structs.Task{Params: `{"action":"` + action + `"}`}
			result := cmd.Execute(task)
			// services and service-registry may need elevated permissions
			if result.Status == "error" {
				if strings.Contains(result.Output, "SCM") || strings.Contains(result.Output, "registry") {
					t.Skip("Need elevated permissions")
				}
			}
		})
	}
}

func TestWinPrivescCheckWritable_DLLHijackTargets(t *testing.T) {
	result := winPrivescCheckWritable()
	if result.Status != "success" {
		t.Errorf("expected success, got %q", result.Status)
	}

	// Should mention DLL hijack target directories section
	if !strings.Contains(result.Output, "DLL Hijack Target") {
		t.Error("expected DLL Hijack Target Directories section in output")
	}
}

func TestIsFileWritable_NonExistent(t *testing.T) {
	if isFileWritable(`C:\nonexistent\path\file.exe`) {
		t.Error("expected non-existent file to not be writable")
	}
}

func TestIsFileWritable_SystemFile(t *testing.T) {
	// System32 files should not be writable by normal users
	if isFileWritable(`C:\Windows\System32\kernel32.dll`) {
		t.Log("kernel32.dll is writable — running as admin/SYSTEM")
	}
}

func TestPrivescCheckCommand_AllNewActions(t *testing.T) {
	// Verify all new actions from DLL and service-registry features are routed correctly
	cmd := &PrivescCheckCommand{}
	newActions := []string{"dll-hijack", "dll-sideload", "service-registry"}

	for _, action := range newActions {
		t.Run(action, func(t *testing.T) {
			task := structs.Task{Params: `{"action":"` + action + `"}`}
			result := cmd.Execute(task)
			// Should not return "Unknown action" error
			if result.Status == "error" && strings.Contains(result.Output, "Unknown action") {
				t.Errorf("action %q returned Unknown action error", action)
			}
		})
	}
}
