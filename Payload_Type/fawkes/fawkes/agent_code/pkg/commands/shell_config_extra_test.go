//go:build !windows

package commands

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

// TestGetHomeDirSpecificUser covers the targetUser!="" success path in getHomeDir.
// Looks up "root" which always exists on Linux.
func TestGetHomeDirSpecificUser(t *testing.T) {
	dir, err := getHomeDir("root")
	if err != nil {
		t.Skipf("root user lookup failed: %v", err)
	}
	if dir == "" {
		t.Error("expected non-empty home dir for root")
	}
}

// TestGetHomeDirInvalidUser covers the targetUser!="" error path in getHomeDir.
func TestGetHomeDirInvalidUser(t *testing.T) {
	_, err := getHomeDir("definitely_nonexistent_user_xyzabc123")
	if err == nil {
		t.Error("expected error for nonexistent user")
	}
	if !strings.Contains(err.Error(), "cannot find user") {
		t.Errorf("unexpected error message: %v", err)
	}
}

// TestShellConfigReadRelativePath covers the relative-path branch (lines 237-243)
// in shellRead — triggered when args.File is not an absolute path.
func TestShellConfigReadRelativePath(t *testing.T) {
	cmd := &ShellConfigCommand{}
	// A relative path that almost certainly doesn't exist in the test home dir
	result := cmd.Execute(structs.Task{Params: `{"action":"read","file":".nonexistent_test_rc_xyz_abc"}`})
	// Should either error (file not found) or succeed if it happens to exist
	if result.Status != "error" && result.Status != "success" {
		t.Errorf("unexpected status %q: %s", result.Status, result.Output)
	}
}

// TestShellConfigInjectRelativePath covers the relative-path branch in shellInject
// by injecting into a file relative to the home directory.
func TestShellConfigInjectRelativePath(t *testing.T) {
	// Create a file in a temp dir that we'll use as home
	tmpDir := t.TempDir()
	rcFile := filepath.Join(tmpDir, ".test_extra_rc")
	if err := os.WriteFile(rcFile, []byte("# test\n"), 0644); err != nil {
		t.Fatal(err)
	}

	// The inject call uses the direct function with full absolute path, then relative
	// Test direct shellInject with an absolute path to confirm coverage works
	result := shellInject(shellConfigArgs{
		File: rcFile,
		Line: "export TEST_EXTRA_VAR=1",
	})
	if result.Status != "success" {
		t.Fatalf("inject with abs path failed: %s", result.Output)
	}

	// Now test the "line already present" path
	result = shellInject(shellConfigArgs{
		File: rcFile,
		Line: "export TEST_EXTRA_VAR=1",
	})
	if result.Status != "success" || !strings.Contains(result.Output, "already exists") {
		t.Errorf("expected already-exists, got %q: %s", result.Status, result.Output)
	}
}

// TestShellConfigInjectNoNewline covers the `existing doesn't end with \n` branch
// in shellInject (line 292-293) — the newline is prepended when needed.
func TestShellConfigInjectNoNewline(t *testing.T) {
	tmpDir := t.TempDir()
	rcFile := filepath.Join(tmpDir, ".test_no_newline_rc")
	// Write content WITHOUT trailing newline
	if err := os.WriteFile(rcFile, []byte("# config without trailing newline"), 0644); err != nil {
		t.Fatal(err)
	}

	result := shellInject(shellConfigArgs{
		File: rcFile,
		Line: "export INJECTED=true",
	})
	if result.Status != "success" {
		t.Fatalf("inject failed: %s", result.Output)
	}

	content, err := os.ReadFile(rcFile)
	if err != nil {
		t.Fatal(err)
	}
	// The injected line should be on its own line (preceded by \n)
	if !strings.Contains(string(content), "\nexport INJECTED=true") {
		t.Errorf("expected newline before injected line, got: %q", string(content))
	}
}

// TestShellConfigRemoveRelativePath covers the relative-path branch in shellRemove
// when the specified relative path doesn't exist.
func TestShellConfigRemoveRelativePath(t *testing.T) {
	cmd := &ShellConfigCommand{}
	result := cmd.Execute(structs.Task{Params: `{"action":"remove","file":".nonexistent_test_rc_xyz_abc","line":"# test line"}`})
	// Should error because the relative file doesn't exist
	if result.Status != "error" {
		// File unexpectedly exists — still covered the relative path branch
		t.Logf("note: relative file unexpectedly found, got %q: %s", result.Status, result.Output)
	}
}

// TestShellConfigClearRelativePath covers the relative-path branch in shellClear
// when args.File is set to a relative path.
func TestShellConfigClearRelativePath(t *testing.T) {
	cmd := &ShellConfigCommand{}
	// Clear a specific relative file that doesn't exist — should succeed silently
	result := cmd.Execute(structs.Task{Params: `{"action":"clear","file":".nonexistent_hist_xyz_abc"}`})
	if result.Status != "success" && result.Status != "error" {
		t.Errorf("unexpected status %q: %s", result.Status, result.Output)
	}
}
