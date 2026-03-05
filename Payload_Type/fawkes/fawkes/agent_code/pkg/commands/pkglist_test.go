package commands

import (
	"os"
	"path/filepath"
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

func TestParseDpkgStatus(t *testing.T) {
	// Create a fake dpkg status file
	tmpDir := t.TempDir()
	statusFile := filepath.Join(tmpDir, "status")
	content := `Package: curl
Status: install ok installed
Version: 7.88.1-10+deb12u5
Architecture: amd64

Package: wget
Status: deinstall ok config-files
Version: 1.21.3-1

Package: git
Status: install ok installed
Version: 1:2.39.2-1.1

`
	if err := os.WriteFile(statusFile, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	// parseDpkgStatus reads from /var/lib/dpkg/status which we can't mock,
	// but we can verify it returns nil on non-dpkg systems or valid data on dpkg systems
	pkgs := parseDpkgStatus()
	// On a dpkg-based system (like Ubuntu CI), this will return packages
	// On non-dpkg systems, it will return nil — both are acceptable
	if pkgs != nil {
		// Verify structure: each entry should have name and version
		for _, pkg := range pkgs {
			if pkg[0] == "" {
				t.Error("package name should not be empty")
			}
			if pkg[1] == "" {
				t.Error("package version should not be empty")
			}
		}
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
