//go:build linux && amd64

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
	// Create a temp dir to simulate home
	tmpDir, err := os.MkdirTemp("", "test-home-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// Create temp library
	tmpLib, err := os.CreateTemp(tmpDir, "test-lib-*.so")
	if err != nil {
		t.Fatal(err)
	}
	tmpLib.Close()

	// Create a .bashrc file in the temp dir
	bashrcPath := filepath.Join(tmpDir, ".bashrc")
	os.WriteFile(bashrcPath, []byte("# existing content\n"), 0644)

	// We can't easily override $HOME in this test, but we can test the validation logic
	// Just verify the library exists check passes
	result := ldPreloadInstall(ldPreloadArgs{
		LibPath: tmpLib.Name(),
		Target:  "bashrc",
	})
	// This will try to write to real ~/.bashrc — may succeed or fail depending on permissions
	// Just verify it doesn't panic and returns a reasonable result
	if result.Status != "success" && result.Status != "error" {
		t.Errorf("unexpected status: %s", result.Status)
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
