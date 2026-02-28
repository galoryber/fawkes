//go:build linux

package commands

import (
	"os"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestScreenshotLinuxCommand_Name(t *testing.T) {
	cmd := &ScreenshotLinuxCommand{}
	if cmd.Name() != "screenshot" {
		t.Errorf("expected 'screenshot', got %q", cmd.Name())
	}
}

func TestScreenshotLinuxCommand_Description(t *testing.T) {
	cmd := &ScreenshotLinuxCommand{}
	if cmd.Description() == "" {
		t.Error("description should not be empty")
	}
	if !strings.Contains(cmd.Description(), "screenshot") {
		t.Errorf("description should mention screenshot: %s", cmd.Description())
	}
}

func TestScreenshotLinuxCommand_NoDisplay(t *testing.T) {
	// Save and clear display env vars
	origDisplay := os.Getenv("DISPLAY")
	origWayland := os.Getenv("WAYLAND_DISPLAY")
	os.Unsetenv("DISPLAY")
	os.Unsetenv("WAYLAND_DISPLAY")
	defer func() {
		if origDisplay != "" {
			os.Setenv("DISPLAY", origDisplay)
		}
		if origWayland != "" {
			os.Setenv("WAYLAND_DISPLAY", origWayland)
		}
	}()

	cmd := &ScreenshotLinuxCommand{}
	// Need a task with Job.SendFileToMythic channel to avoid panic
	// But since no display is set, it should return error before needing the channel
	result := cmd.Execute(structs.Task{})
	if result.Status != "error" {
		t.Errorf("expected error when no display is set, got %s", result.Status)
	}
	if !strings.Contains(result.Output, "No display server detected") {
		t.Errorf("expected display server error, got: %s", result.Output)
	}
}

func TestTryScreenshotTools_NoToolsAvailable(t *testing.T) {
	tmpFile := "/tmp/screenshot_test_nonexistent.png"
	defer os.Remove(tmpFile)

	tools := []screenshotTool{
		{"nonexistent_tool_abc123", []string{tmpFile}},
		{"nonexistent_tool_xyz789", []string{tmpFile}},
	}

	err := tryScreenshotTools(tmpFile, tools)
	if err == nil {
		t.Error("expected error when no screenshot tools are available")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("expected 'not found' in error, got: %s", err.Error())
	}
}

func TestTryScreenshotTools_EmptyList(t *testing.T) {
	err := tryScreenshotTools("/tmp/test.png", nil)
	if err == nil {
		t.Error("expected error for empty tool list")
	}
	if !strings.Contains(err.Error(), "no screenshot tools available") {
		t.Errorf("expected 'no screenshot tools' error, got: %s", err.Error())
	}
}
