//go:build windows

package commands

import (
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestWinPrivescCheckRegistry_Output(t *testing.T) {
	result := winPrivescCheckRegistry()
	if result.Status != "success" {
		t.Errorf("expected success, got %q: %s", result.Status, result.Output)
	}

	// Should contain all sections
	sections := []string{
		"AlwaysInstallElevated",
		"Auto-Logon",
		"LSA Protection",
		"WSUS Configuration",
	}
	for _, section := range sections {
		if !strings.Contains(result.Output, section) {
			t.Errorf("expected %q section in output", section)
		}
	}
}

func TestWinPrivescCheckUAC_Output(t *testing.T) {
	result := winPrivescCheckUAC()
	if result.Status != "success" {
		t.Errorf("expected success, got %q: %s", result.Status, result.Output)
	}

	// Should report UAC state
	if !strings.Contains(result.Output, "UAC") && !strings.Contains(result.Output, "EnableLUA") {
		t.Error("expected UAC status in output")
	}
}

func TestWinPrivescCheckUnattend_Output(t *testing.T) {
	result := winPrivescCheckUnattend()
	if result.Status != "success" {
		t.Errorf("expected success, got %q: %s", result.Status, result.Output)
	}

	// Should contain unattended install section
	if !strings.Contains(result.Output, "Unattended install files") {
		t.Error("expected unattended install files section in output")
	}
}

func TestPrivescCheckCommand_RegistryActions(t *testing.T) {
	cmd := &PrivescCheckCommand{}
	actions := []string{"registry", "uac", "unattend"}

	for _, action := range actions {
		t.Run(action, func(t *testing.T) {
			task := structs.Task{Params: `{"action":"` + action + `"}`}
			result := cmd.Execute(task)
			if result.Status != "success" {
				t.Errorf("expected success for %q, got %q: %s", action, result.Status, result.Output)
			}
		})
	}
}

func TestWinPrivescCheckRegistry_CredentialGuard(t *testing.T) {
	result := winPrivescCheckRegistry()
	// Should mention Credential Guard status
	if !strings.Contains(result.Output, "Credential Guard") {
		t.Error("expected Credential Guard section in output")
	}
}

func TestWinPrivescCheckUAC_ConsentBehavior(t *testing.T) {
	result := winPrivescCheckUAC()
	// Should mention consent prompt behavior
	if !strings.Contains(result.Output, "consent") || !strings.Contains(result.Output, "prompt") {
		// Accept either "consent prompt" pattern or UAC disabled output
		if !strings.Contains(result.Output, "DISABLED") {
			t.Error("expected consent prompt behavior or UAC disabled in output")
		}
	}
}

func TestReadRegDWORD_KnownKeys(t *testing.T) {
	// Test reading a known registry key that always exists on Windows
	// HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\CurrentBuildNumber is always present
	// But it's a string, so readRegDWORD returns 0xFFFFFFFF
	val := readRegDWORD(0x80000002, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, "InstallDate")
	// InstallDate should be a non-zero timestamp if it exists
	if val == 0xFFFFFFFF {
		t.Skip("InstallDate not found — might be a minimal Windows install")
	}
	if val == 0 {
		t.Error("expected non-zero InstallDate")
	}
}

func TestReadRegString_KnownKeys(t *testing.T) {
	// Test reading a known string value
	val := readRegString(0x80000002, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, "ProductName")
	if val == "" {
		t.Skip("ProductName not found — might be a minimal Windows install")
	}
	if !strings.Contains(val, "Windows") {
		t.Errorf("expected Windows in ProductName, got %q", val)
	}
}

func TestCountRegValues_KnownKeys(t *testing.T) {
	// KnownDLLs should have multiple values on any Windows system
	count := countRegValues(0x80000002, `SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`)
	if count < 0 {
		t.Skip("Cannot access KnownDLLs — might need elevated permissions")
	}
	if count < 5 {
		t.Errorf("expected at least 5 KnownDLLs, got %d", count)
	}
}

func TestCountRegValues_NonExistent(t *testing.T) {
	count := countRegValues(0x80000002, `SOFTWARE\NonExistent\Key\Path`)
	if count != -1 {
		t.Errorf("expected -1 for non-existent key, got %d", count)
	}
}
