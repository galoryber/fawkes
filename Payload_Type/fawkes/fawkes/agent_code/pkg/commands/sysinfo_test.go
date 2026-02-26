package commands

import (
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestSysinfoName(t *testing.T) {
	cmd := &SysinfoCommand{}
	if cmd.Name() != "sysinfo" {
		t.Errorf("expected 'sysinfo', got '%s'", cmd.Name())
	}
}

func TestSysinfoDescription(t *testing.T) {
	cmd := &SysinfoCommand{}
	if cmd.Description() == "" {
		t.Error("description should not be empty")
	}
}

func TestSysinfoExecute(t *testing.T) {
	cmd := &SysinfoCommand{}
	result := cmd.Execute(structs.Task{Params: ""})
	if result.Status != "success" {
		t.Errorf("expected success, got %s: %s", result.Status, result.Output)
	}
	if !result.Completed {
		t.Error("expected completed=true")
	}
}

func TestSysinfoContainsCommonFields(t *testing.T) {
	cmd := &SysinfoCommand{}
	result := cmd.Execute(structs.Task{Params: ""})

	requiredFields := []string{
		"System Information",
		"Hostname:",
		"OS:",
		"Architecture:",
		"CPUs:",
		"PID:",
		"Time:",
		"Timezone:",
	}

	for _, field := range requiredFields {
		if !strings.Contains(result.Output, field) {
			t.Errorf("output missing expected field: %s", field)
		}
	}
}

func TestSysinfoHasPlatformSection(t *testing.T) {
	cmd := &SysinfoCommand{}
	result := cmd.Execute(structs.Task{Params: ""})

	// Should have at least one platform section
	hasPlatform := strings.Contains(result.Output, "Windows Details") ||
		strings.Contains(result.Output, "Linux Details") ||
		strings.Contains(result.Output, "macOS Details")
	if !hasPlatform {
		t.Error("output should contain platform-specific section")
	}
}

func TestSysinfoNoParams(t *testing.T) {
	cmd := &SysinfoCommand{}
	// Should work with empty params
	result := cmd.Execute(structs.Task{Params: ""})
	if result.Status != "success" {
		t.Errorf("should succeed with no params: %s", result.Output)
	}
}
