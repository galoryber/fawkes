package commands

import (
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestPkgListName(t *testing.T) {
	cmd := &PkgListCommand{}
	if cmd.Name() != "pkg-list" {
		t.Errorf("Name() = %q, want %q", cmd.Name(), "pkg-list")
	}
}

func TestPkgListDescription(t *testing.T) {
	cmd := &PkgListCommand{}
	if cmd.Description() == "" {
		t.Error("Description() should not be empty")
	}
}

func TestPkgListExecute(t *testing.T) {
	cmd := &PkgListCommand{}
	task := structs.Task{Params: ""}
	result := cmd.Execute(task)
	if result.Status != "success" {
		t.Errorf("Status = %q, want %q", result.Status, "success")
	}
	if !result.Completed {
		t.Error("Completed should be true")
	}
	if !strings.Contains(result.Output, "Installed") {
		t.Error("Output should contain 'Installed'")
	}
}

func TestRunQuietCommand(t *testing.T) {
	// Test with a command that exists
	output := runQuietCommand("echo", "hello")
	if !strings.Contains(output, "hello") {
		t.Errorf("runQuietCommand('echo hello') = %q, want to contain 'hello'", output)
	}
}

func TestRunQuietCommandFailure(t *testing.T) {
	// Test with a nonexistent command
	output := runQuietCommand("nonexistent_command_xyz")
	if output != "" {
		t.Errorf("runQuietCommand for nonexistent command should return empty, got %q", output)
	}
}

func TestPkgListLinux(t *testing.T) {
	output := pkgListLinux()
	if !strings.Contains(output, "Installed Packages") {
		t.Error("Output should contain header")
	}
	// Should either find a package manager or report none found
	hasPkgMgr := strings.Contains(output, "Package Manager:") ||
		strings.Contains(output, "Snap packages:") ||
		strings.Contains(output, "Flatpak") ||
		strings.Contains(output, "No supported package manager")
	if !hasPkgMgr {
		t.Error("Output should report on package managers")
	}
}
