//go:build !windows

package commands

import (
	"os/user"
	"runtime"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestWhoamiCommandName(t *testing.T) {
	cmd := &WhoamiCommand{}
	if cmd.Name() != "whoami" {
		t.Errorf("expected 'whoami', got %q", cmd.Name())
	}
}

func TestWhoamiCommandDescription(t *testing.T) {
	cmd := &WhoamiCommand{}
	if cmd.Description() == "" {
		t.Error("description should not be empty")
	}
}

func TestWhoamiReturnsUser(t *testing.T) {
	cmd := &WhoamiCommand{}
	task := structs.NewTask("t", "whoami", "")
	result := cmd.Execute(task)
	if result.Status != "success" {
		t.Errorf("expected success, got %q: %s", result.Status, result.Output)
	}

	u, _ := user.Current()
	if !strings.Contains(result.Output, u.Username) {
		t.Errorf("output should contain username %q, got %q", u.Username, result.Output)
	}
	if !strings.Contains(result.Output, u.Uid) {
		t.Errorf("output should contain UID %q", u.Uid)
	}
}

func TestWhoamiShowsGroups(t *testing.T) {
	cmd := &WhoamiCommand{}
	task := structs.NewTask("t", "whoami", "")
	result := cmd.Execute(task)
	if result.Status != "success" {
		t.Fatalf("expected success, got %q", result.Status)
	}
	if !strings.Contains(result.Output, "Groups:") {
		t.Error("output should contain Groups section")
	}
}

func TestWhoamiShowsHostname(t *testing.T) {
	cmd := &WhoamiCommand{}
	task := structs.NewTask("t", "whoami", "")
	result := cmd.Execute(task)
	if result.Status != "success" {
		t.Fatalf("expected success, got %q", result.Status)
	}
	if !strings.Contains(result.Output, "Host:") {
		t.Error("output should contain Host section")
	}
}

func TestWhoamiLinuxCapabilities(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux-only test")
	}

	cmd := &WhoamiCommand{}
	task := structs.NewTask("t", "whoami", "")
	result := cmd.Execute(task)
	if result.Status != "success" {
		t.Fatalf("expected success, got %q: %s", result.Status, result.Output)
	}

	// On Linux, output should contain capability information
	if !strings.Contains(result.Output, "Capabilit") {
		t.Error("Linux whoami should include capabilities section")
	}
}

func TestWhoamiLinuxContext(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux-only test")
	}

	lines := whoamiLinuxContext()
	// Should return at least the capabilities section
	if len(lines) == 0 {
		t.Error("whoamiLinuxContext should return at least capability info on Linux")
	}

	found := false
	for _, line := range lines {
		if strings.Contains(line, "Capabilit") || strings.Contains(line, "CAP_") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected capability info in output, got: %v", lines)
	}
}

func TestReadLinuxCapabilities(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux-only test")
	}

	capEff, capPrm := readLinuxCapabilities()
	// On any Linux system, CapEff should be a hex string
	if capEff == "" {
		t.Error("CapEff should not be empty on Linux")
	}
	if capPrm == "" {
		t.Error("CapPrm should not be empty on Linux")
	}
	// Should be valid hex
	if len(capEff) < 16 {
		t.Errorf("CapEff too short: %q", capEff)
	}
}

func TestDetectContainerNotInContainer(t *testing.T) {
	// This test may or may not detect a container depending on environment.
	// Just verify it doesn't panic.
	result := detectContainer()
	t.Logf("detectContainer() = %q", result)
}
