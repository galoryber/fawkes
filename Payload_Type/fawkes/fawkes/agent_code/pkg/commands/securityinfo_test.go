package commands

import (
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestSecurityInfoName(t *testing.T) {
	cmd := &SecurityInfoCommand{}
	if cmd.Name() != "security-info" {
		t.Errorf("Name() = %q, want %q", cmd.Name(), "security-info")
	}
}

func TestSecurityInfoDescription(t *testing.T) {
	cmd := &SecurityInfoCommand{}
	if cmd.Description() == "" {
		t.Error("Description() should not be empty")
	}
}

func TestSecurityInfoExecute(t *testing.T) {
	cmd := &SecurityInfoCommand{}
	task := structs.Task{Params: ""}
	result := cmd.Execute(task)
	if result.Status != "success" {
		t.Errorf("Status = %q, want %q", result.Status, "success")
	}
	if !result.Completed {
		t.Error("Completed should be true")
	}
	if !strings.Contains(result.Output, "Security Posture Report") {
		t.Error("Output should contain report header")
	}
}

func TestSecurityInfoLinux(t *testing.T) {
	controls := securityInfoLinux()
	if len(controls) == 0 {
		t.Error("Should return at least one security control")
	}
	// Should check SELinux, AppArmor, and ASLR at minimum
	names := make(map[string]bool)
	for _, ctl := range controls {
		names[ctl.Name] = true
	}
	if !names["SELinux"] && !names["AppArmor"] {
		t.Error("Should check at least SELinux or AppArmor")
	}
}

func TestSecurityInfoOutputFormat(t *testing.T) {
	cmd := &SecurityInfoCommand{}
	task := structs.Task{Params: ""}
	result := cmd.Execute(task)

	// Should have summary line
	if !strings.Contains(result.Output, "security controls active") {
		t.Error("Output should contain security controls summary")
	}
}

func TestReadFileQuiet(t *testing.T) {
	// Test with a file that exists
	content := readFileQuiet("/proc/self/status")
	if content == "" {
		t.Error("readFileQuiet should read /proc/self/status")
	}

	// Test with nonexistent file
	content = readFileQuiet("/nonexistent/path/xyz")
	if content != "" {
		t.Error("readFileQuiet should return empty for nonexistent files")
	}
}
