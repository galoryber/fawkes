//go:build windows

package commands

import (
	"encoding/json"
	"strings"
	"testing"

	"fawkes/pkg/structs"

	"golang.org/x/sys/windows/registry"
)

func TestPersistCommand_NameAndDescription(t *testing.T) {
	cmd := &PersistCommand{}
	if cmd.Name() != "persist" {
		t.Errorf("Name() = %q, want %q", cmd.Name(), "persist")
	}
	if cmd.Description() == "" {
		t.Error("Description() should not be empty")
	}
}

func TestPersistCommand_EmptyParams(t *testing.T) {
	cmd := &PersistCommand{}
	result := cmd.Execute(structs.Task{Params: ""})
	if result.Status != "error" {
		t.Errorf("expected error for empty params, got %q", result.Status)
	}
}

func TestPersistCommand_InvalidJSON(t *testing.T) {
	cmd := &PersistCommand{}
	result := cmd.Execute(structs.Task{Params: "not json"})
	if result.Status != "error" {
		t.Errorf("expected error for invalid JSON, got %q", result.Status)
	}
}

func TestPersistCommand_UnknownMethod(t *testing.T) {
	cmd := &PersistCommand{}
	params, _ := json.Marshal(persistArgs{Method: "unknown-method"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error for unknown method, got %q", result.Status)
	}
	if !strings.Contains(result.Output, "Unknown method") {
		t.Errorf("expected 'Unknown method' in output, got: %s", result.Output)
	}
}

func TestPersistCommand_UnknownAction(t *testing.T) {
	cmd := &PersistCommand{}
	for _, method := range []string{"registry", "com-hijack", "screensaver"} {
		t.Run(method, func(t *testing.T) {
			params, _ := json.Marshal(persistArgs{Method: method, Action: "badaction", Name: "test"})
			result := cmd.Execute(structs.Task{Params: string(params)})
			if result.Status != "error" {
				t.Errorf("expected error for unknown action on %s, got %q", method, result.Status)
			}
		})
	}
}

func TestPersistCommand_RegistryMissingName(t *testing.T) {
	cmd := &PersistCommand{}
	params, _ := json.Marshal(persistArgs{Method: "registry", Action: "install"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error for missing name, got %q", result.Status)
	}
}

func TestPersistCommand_RegistryBadHive(t *testing.T) {
	cmd := &PersistCommand{}
	params, _ := json.Marshal(persistArgs{Method: "registry", Action: "install", Name: "test", Hive: "INVALID"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error for invalid hive, got %q", result.Status)
	}
}

// --- COM Hijack Tests ---

func TestPersistCOMHijack_Install(t *testing.T) {
	// Use a unique test CLSID that won't conflict with anything
	testCLSID := "{00000000-0000-0000-0000-FAWKESTEST01}"
	testPath := `C:\test\fawkes_test.dll`

	result := persistCOMHijack(persistArgs{
		Method: "com-hijack",
		Action: "install",
		Path:   testPath,
		CLSID:  testCLSID,
	})
	if result.Status != "success" {
		t.Fatalf("install failed: %s", result.Output)
	}

	// Verify registry key was created
	keyPath := `Software\Classes\CLSID\` + testCLSID + `\InprocServer32`
	key, err := registry.OpenKey(registry.CURRENT_USER, keyPath, registry.QUERY_VALUE)
	if err != nil {
		t.Fatalf("failed to open created key: %v", err)
	}

	val, _, err := key.GetStringValue("")
	key.Close()
	if err != nil {
		t.Fatalf("failed to read default value: %v", err)
	}
	if val != testPath {
		t.Errorf("default value = %q, want %q", val, testPath)
	}

	// Cleanup
	registry.DeleteKey(registry.CURRENT_USER, keyPath)
	registry.DeleteKey(registry.CURRENT_USER, `Software\Classes\CLSID\`+testCLSID)
}

func TestPersistCOMHijack_Remove(t *testing.T) {
	testCLSID := "{00000000-0000-0000-0000-FAWKESTEST02}"
	testPath := `C:\test\fawkes_test.dll`

	// First install
	result := persistCOMHijack(persistArgs{
		Method: "com-hijack",
		Action: "install",
		Path:   testPath,
		CLSID:  testCLSID,
	})
	if result.Status != "success" {
		t.Fatalf("install failed: %s", result.Output)
	}

	// Then remove
	result = persistCOMHijack(persistArgs{
		Method: "com-hijack",
		Action: "remove",
		CLSID:  testCLSID,
	})
	if result.Status != "success" {
		t.Fatalf("remove failed: %s", result.Output)
	}

	// Verify key is gone
	keyPath := `Software\Classes\CLSID\` + testCLSID + `\InprocServer32`
	_, err := registry.OpenKey(registry.CURRENT_USER, keyPath, registry.QUERY_VALUE)
	if err == nil {
		t.Error("key should have been deleted")
		registry.DeleteKey(registry.CURRENT_USER, keyPath)
		registry.DeleteKey(registry.CURRENT_USER, `Software\Classes\CLSID\`+testCLSID)
	}
}

func TestPersistCOMHijack_DefaultCLSID(t *testing.T) {
	// When no CLSID is provided, should use the default
	testPath := `C:\test\fawkes_default_clsid.dll`

	result := persistCOMHijack(persistArgs{
		Method: "com-hijack",
		Action: "install",
		Path:   testPath,
	})
	if result.Status != "success" {
		t.Fatalf("install with default CLSID failed: %s", result.Output)
	}
	if !strings.Contains(result.Output, defaultCLSID) {
		t.Errorf("output should mention default CLSID, got: %s", result.Output)
	}

	// Cleanup
	keyPath := `Software\Classes\CLSID\` + defaultCLSID + `\InprocServer32`
	registry.DeleteKey(registry.CURRENT_USER, keyPath)
	registry.DeleteKey(registry.CURRENT_USER, `Software\Classes\CLSID\`+defaultCLSID)
}

func TestPersistCOMHijack_NormalizeCLSID(t *testing.T) {
	// CLSID without braces should get braces added
	testCLSID := "00000000-0000-0000-0000-FAWKESTEST03"
	expectedCLSID := "{" + testCLSID + "}"
	testPath := `C:\test\fawkes_norm.dll`

	result := persistCOMHijack(persistArgs{
		Method: "com-hijack",
		Action: "install",
		Path:   testPath,
		CLSID:  testCLSID,
	})
	if result.Status != "success" {
		t.Fatalf("install failed: %s", result.Output)
	}
	if !strings.Contains(result.Output, expectedCLSID) {
		t.Errorf("output should use normalized CLSID %s, got: %s", expectedCLSID, result.Output)
	}

	// Cleanup
	keyPath := `Software\Classes\CLSID\` + expectedCLSID + `\InprocServer32`
	registry.DeleteKey(registry.CURRENT_USER, keyPath)
	registry.DeleteKey(registry.CURRENT_USER, `Software\Classes\CLSID\`+expectedCLSID)
}

func TestPersistCOMHijack_ThreadingModel(t *testing.T) {
	testCLSID := "{00000000-0000-0000-0000-FAWKESTEST04}"
	testPath := `C:\test\fawkes_tm.dll`

	result := persistCOMHijack(persistArgs{
		Method: "com-hijack",
		Action: "install",
		Path:   testPath,
		CLSID:  testCLSID,
	})
	if result.Status != "success" {
		t.Fatalf("install failed: %s", result.Output)
	}

	keyPath := `Software\Classes\CLSID\` + testCLSID + `\InprocServer32`
	key, err := registry.OpenKey(registry.CURRENT_USER, keyPath, registry.QUERY_VALUE)
	if err != nil {
		t.Fatalf("failed to open key: %v", err)
	}

	tm, _, err := key.GetStringValue("ThreadingModel")
	key.Close()
	if err != nil {
		t.Fatalf("failed to read ThreadingModel: %v", err)
	}
	if tm != "Both" {
		t.Errorf("ThreadingModel = %q, want %q", tm, "Both")
	}

	// Cleanup
	registry.DeleteKey(registry.CURRENT_USER, keyPath)
	registry.DeleteKey(registry.CURRENT_USER, `Software\Classes\CLSID\`+testCLSID)
}

func TestPersistCOMHijack_RemoveNonexistent(t *testing.T) {
	result := persistCOMHijack(persistArgs{
		Method: "com-hijack",
		Action: "remove",
		CLSID:  "{00000000-0000-0000-0000-DOESNOTEXIST}",
	})
	if result.Status != "error" {
		t.Errorf("expected error for removing nonexistent CLSID, got %q", result.Status)
	}
}

// --- Screensaver Tests ---

func TestPersistScreensaver_Install(t *testing.T) {
	testPath := `C:\test\fawkes_screensaver.exe`

	result := persistScreensaver(persistArgs{
		Method:  "screensaver",
		Action:  "install",
		Path:    testPath,
		Timeout: "120",
	})
	if result.Status != "success" {
		t.Fatalf("install failed: %s", result.Output)
	}

	// Verify registry values
	key, err := registry.OpenKey(registry.CURRENT_USER, `Control Panel\Desktop`, registry.QUERY_VALUE)
	if err != nil {
		t.Fatalf("failed to open Desktop key: %v", err)
	}
	defer key.Close()

	scrnsave, _, err := key.GetStringValue("SCRNSAVE.EXE")
	if err != nil {
		t.Fatalf("failed to read SCRNSAVE.EXE: %v", err)
	}
	if scrnsave != testPath {
		t.Errorf("SCRNSAVE.EXE = %q, want %q", scrnsave, testPath)
	}

	active, _, _ := key.GetStringValue("ScreenSaveActive")
	if active != "1" {
		t.Errorf("ScreenSaveActive = %q, want %q", active, "1")
	}

	timeout, _, _ := key.GetStringValue("ScreenSaveTimeout")
	if timeout != "120" {
		t.Errorf("ScreenSaveTimeout = %q, want %q", timeout, "120")
	}

	secure, _, _ := key.GetStringValue("ScreenSaverIsSecure")
	if secure != "0" {
		t.Errorf("ScreenSaverIsSecure = %q, want %q", secure, "0")
	}

	// Cleanup
	t.Cleanup(func() {
		persistScreensaver(persistArgs{Method: "screensaver", Action: "remove"})
	})
}

func TestPersistScreensaver_DefaultTimeout(t *testing.T) {
	testPath := `C:\test\fawkes_ss_default.exe`

	result := persistScreensaver(persistArgs{
		Method: "screensaver",
		Action: "install",
		Path:   testPath,
	})
	if result.Status != "success" {
		t.Fatalf("install with default timeout failed: %s", result.Output)
	}
	if !strings.Contains(result.Output, "60 seconds") {
		t.Errorf("expected default 60 seconds in output, got: %s", result.Output)
	}

	// Cleanup
	t.Cleanup(func() {
		persistScreensaver(persistArgs{Method: "screensaver", Action: "remove"})
	})
}

func TestPersistScreensaver_Remove(t *testing.T) {
	testPath := `C:\test\fawkes_ss_remove.exe`

	// First install
	result := persistScreensaver(persistArgs{
		Method: "screensaver",
		Action: "install",
		Path:   testPath,
	})
	if result.Status != "success" {
		t.Fatalf("install failed: %s", result.Output)
	}

	// Then remove
	result = persistScreensaver(persistArgs{
		Method: "screensaver",
		Action: "remove",
	})
	if result.Status != "success" {
		t.Fatalf("remove failed: %s", result.Output)
	}

	// Verify SCRNSAVE.EXE is gone
	key, err := registry.OpenKey(registry.CURRENT_USER, `Control Panel\Desktop`, registry.QUERY_VALUE)
	if err != nil {
		t.Fatalf("failed to open Desktop key: %v", err)
	}
	defer key.Close()

	_, _, err = key.GetStringValue("SCRNSAVE.EXE")
	if err == nil {
		t.Error("SCRNSAVE.EXE should have been deleted after remove")
	}

	active, _, _ := key.GetStringValue("ScreenSaveActive")
	if active != "0" {
		t.Errorf("ScreenSaveActive should be '0' after remove, got %q", active)
	}
}

// --- List Tests ---

func TestPersistList(t *testing.T) {
	result := listPersistence(persistArgs{Method: "list"})
	if result.Status != "success" {
		t.Fatalf("list failed: %s", result.Output)
	}
	// Should contain section headers for all persistence types
	expected := []string{
		"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
		"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
		"Startup Folder",
		"COM Hijacking",
		"Screensaver",
	}
	for _, s := range expected {
		if !strings.Contains(result.Output, s) {
			t.Errorf("list output should contain %q, got:\n%s", s, result.Output)
		}
	}
}

func TestPersistList_DetectsCOMHijack(t *testing.T) {
	testCLSID := "{42aedc87-2188-41fd-b9a3-0c966feabec1}"
	testPath := `C:\test\fawkes_list_com.dll`

	// Install COM hijack
	persistCOMHijack(persistArgs{
		Method: "com-hijack",
		Action: "install",
		Path:   testPath,
		CLSID:  testCLSID,
	})

	// List should detect it
	result := listPersistence(persistArgs{Method: "list"})
	if result.Status != "success" {
		t.Fatalf("list failed: %s", result.Output)
	}
	if !strings.Contains(result.Output, testPath) {
		t.Errorf("list should detect COM hijack entry with path %s, got:\n%s", testPath, result.Output)
	}

	// Cleanup
	keyPath := `Software\Classes\CLSID\` + testCLSID + `\InprocServer32`
	registry.DeleteKey(registry.CURRENT_USER, keyPath)
	registry.DeleteKey(registry.CURRENT_USER, `Software\Classes\CLSID\`+testCLSID)
}
