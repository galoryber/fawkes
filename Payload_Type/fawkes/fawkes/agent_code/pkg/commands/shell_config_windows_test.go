//go:build windows

package commands

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestShellConfigWindowsName(t *testing.T) {
	cmd := &ShellConfigCommand{}
	if cmd.Name() != "shell-config" {
		t.Errorf("expected 'shell-config', got %q", cmd.Name())
	}
}

func TestShellConfigWindowsEmptyParams(t *testing.T) {
	cmd := &ShellConfigCommand{}
	result := cmd.Execute(structs.Task{Params: ""})
	if result.Status != "error" {
		t.Errorf("expected error for empty params, got %q", result.Status)
	}
}

func TestShellConfigWindowsInvalidAction(t *testing.T) {
	cmd := &ShellConfigCommand{}
	result := cmd.Execute(structs.Task{Params: `{"action":"bogus"}`})
	if result.Status != "error" {
		t.Errorf("expected error for invalid action, got %q", result.Status)
	}
}

func TestShellConfigWindowsList(t *testing.T) {
	cmd := &ShellConfigCommand{}
	result := cmd.Execute(structs.Task{Params: `{"action":"list"}`})
	if result.Status != "success" {
		t.Errorf("expected success for list, got %q: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "PowerShell Profile") {
		t.Error("list output should mention PowerShell Profile")
	}
	// Should list all 8 profile locations
	if !strings.Contains(result.Output, "PS7") || !strings.Contains(result.Output, "PS5") {
		t.Error("list output should mention PS7 and PS5 profiles")
	}
}

func TestShellConfigWindowsReadMissing(t *testing.T) {
	cmd := &ShellConfigCommand{}
	result := cmd.Execute(structs.Task{Params: `{"action":"read"}`})
	if result.Status != "error" {
		t.Errorf("expected error for missing file, got %q", result.Status)
	}
}

func TestShellConfigWindowsReadNonexistent(t *testing.T) {
	cmd := &ShellConfigCommand{}
	result := cmd.Execute(structs.Task{Params: `{"action":"read","file":"C:\\nonexistent\\profile.ps1"}`})
	if result.Status != "error" {
		t.Errorf("expected error for nonexistent file, got %q", result.Status)
	}
}

func TestShellConfigWindowsInjectRemoveLifecycle(t *testing.T) {
	// Create a temp dir to simulate profile location
	tmpDir := t.TempDir()
	profilePath := filepath.Join(tmpDir, "Microsoft.PowerShell_profile.ps1")
	testLine := "Write-Host 'Test persistence line'"

	cmd := &ShellConfigCommand{}

	// Inject
	result := cmd.Execute(structs.Task{Params: `{"action":"inject","file":"` + strings.ReplaceAll(profilePath, `\`, `\\`) + `","line":"` + testLine + `","comment":"fawkes-test"}`})
	if result.Status != "success" {
		t.Fatalf("inject failed: %s", result.Output)
	}
	if !strings.Contains(result.Output, "Injected") {
		t.Error("expected 'Injected' in output")
	}

	// Verify file contents
	content, err := os.ReadFile(profilePath)
	if err != nil {
		t.Fatalf("could not read profile: %v", err)
	}
	if !strings.Contains(string(content), testLine) {
		t.Error("injected line not found in profile")
	}
	if !strings.Contains(string(content), "fawkes-test") {
		t.Error("comment not found in profile")
	}

	// Duplicate injection should be skipped
	result = cmd.Execute(structs.Task{Params: `{"action":"inject","file":"` + strings.ReplaceAll(profilePath, `\`, `\\`) + `","line":"` + testLine + ` # fawkes-test"}`})
	if !strings.Contains(result.Output, "already exists") {
		t.Error("expected duplicate detection")
	}

	// Remove
	result = cmd.Execute(structs.Task{Params: `{"action":"remove","file":"` + strings.ReplaceAll(profilePath, `\`, `\\`) + `","line":"` + testLine + `"}`})
	if result.Status != "success" {
		t.Fatalf("remove failed: %s", result.Output)
	}
	if !strings.Contains(result.Output, "Removed") {
		t.Error("expected 'Removed' in output")
	}

	// Verify removal
	content, _ = os.ReadFile(profilePath)
	if strings.Contains(string(content), testLine) {
		t.Error("line should have been removed")
	}
}

func TestGetPSProfiles(t *testing.T) {
	profiles := getPSProfiles()
	if len(profiles) != 8 {
		t.Errorf("expected 8 profile locations, got %d", len(profiles))
	}

	// Check that we have both PS7 and PS5 profiles
	ps7Count, ps5Count := 0, 0
	for _, p := range profiles {
		if strings.HasPrefix(p.Name, "PS7") {
			ps7Count++
		}
		if strings.HasPrefix(p.Name, "PS5") {
			ps5Count++
		}
	}
	if ps7Count != 4 {
		t.Errorf("expected 4 PS7 profiles, got %d", ps7Count)
	}
	if ps5Count != 4 {
		t.Errorf("expected 4 PS5 profiles, got %d", ps5Count)
	}
}

func TestResolveProfilePath(t *testing.T) {
	// Empty string
	if resolveProfilePath("") != "" {
		t.Error("empty input should return empty")
	}

	// Absolute path
	abs := `C:\test\profile.ps1`
	if resolveProfilePath(abs) != abs {
		t.Errorf("absolute path should be returned as-is, got %q", resolveProfilePath(abs))
	}

	// Profile name matching
	path := resolveProfilePath("PS7 CurrentUser CurrentHost")
	if path == "" || path == "PS7 CurrentUser CurrentHost" {
		t.Error("profile name should resolve to a path")
	}
	if !strings.HasSuffix(path, "Microsoft.PowerShell_profile.ps1") {
		t.Errorf("unexpected resolved path: %s", path)
	}
}
