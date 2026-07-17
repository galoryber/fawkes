//go:build linux

package commands

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLdPreloadList(t *testing.T) {
	result := ldPreloadList()
	if result.Status != "success" {
		t.Errorf("expected success, got: %s", result.Output)
	}
	if !strings.Contains(result.Output, "LD_PRELOAD Configuration") {
		t.Error("expected configuration header in output")
	}
	if !strings.Contains(result.Output, "/etc/ld.so.preload") {
		t.Error("expected ld.so.preload check in output")
	}
	if !strings.Contains(result.Output, "LD_PRELOAD=") {
		t.Error("expected environment variable check in output")
	}
	if !strings.Contains(result.Output, "Shell Profiles") {
		t.Error("expected shell profiles section in output")
	}
}

func TestLdPreloadInstall_MissingLibpath(t *testing.T) {
	result := ldPreloadInstall(ldPreloadArgs{})
	if result.Status != "error" {
		t.Error("expected error for missing libpath")
	}
	if !strings.Contains(result.Output, "libpath") {
		t.Error("expected libpath error message")
	}
}

func TestLdPreloadInstall_LibNotFound(t *testing.T) {
	result := ldPreloadInstall(ldPreloadArgs{
		LibPath: "/nonexistent/lib.so",
	})
	if result.Status != "error" {
		t.Error("expected error for nonexistent library")
	}
	if !strings.Contains(result.Output, "not found") {
		t.Error("expected 'not found' error message")
	}
}

func TestLdPreloadInstall_InvalidTarget(t *testing.T) {
	// Create a temp file to act as our "library"
	tmpFile, err := os.CreateTemp("", "test-lib-*.so")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	result := ldPreloadInstall(ldPreloadArgs{
		LibPath: tmpFile.Name(),
		Target:  "invalid_target",
	})
	if result.Status != "error" {
		t.Error("expected error for invalid target")
	}
	if !strings.Contains(result.Output, "Unknown target") {
		t.Error("expected 'Unknown target' error message")
	}
}

func TestLdPreloadInstall_BashrcTarget(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "test-home-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	origHome := os.Getenv("HOME")
	t.Setenv("HOME", tmpDir)
	defer os.Setenv("HOME", origHome)

	tmpLib, err := os.CreateTemp(tmpDir, "test-lib-*.so")
	if err != nil {
		t.Fatal(err)
	}
	tmpLib.Close()

	bashrcPath := filepath.Join(tmpDir, ".bashrc")
	os.WriteFile(bashrcPath, []byte("# existing content\n"), 0644)

	result := ldPreloadInstall(ldPreloadArgs{
		LibPath: tmpLib.Name(),
		Target:  "bashrc",
	})
	if result.Status != "success" {
		t.Errorf("expected success, got %s: %s", result.Status, result.Output)
	}

	content, err := os.ReadFile(bashrcPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(content), "LD_PRELOAD="+tmpLib.Name()) {
		t.Error("expected LD_PRELOAD line in temp .bashrc")
	}
}

func TestLdPreloadRemove_MissingLibpath(t *testing.T) {
	result := ldPreloadRemove(ldPreloadArgs{})
	if result.Status != "error" {
		t.Error("expected error for missing libpath")
	}
}

func TestLdPreloadRemove_NotFound(t *testing.T) {
	result := ldPreloadRemove(ldPreloadArgs{
		LibPath: "/nonexistent/lib-that-doesnt-exist-anywhere.so",
		Target:  "auto",
	})
	if result.Status != "error" {
		t.Error("expected error when library not found in any file")
	}
	if !strings.Contains(result.Output, "not found") {
		t.Error("expected 'not found' error message")
	}
}
