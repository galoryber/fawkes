//go:build linux

package commands

import (
	"os"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestPrivescCheckCommand_Name(t *testing.T) {
	cmd := &PrivescCheckCommand{}
	if cmd.Name() != "privesc-check" {
		t.Errorf("Expected 'privesc-check', got '%s'", cmd.Name())
	}
}

func TestPrivescCheckCommand_Description(t *testing.T) {
	cmd := &PrivescCheckCommand{}
	if cmd.Description() == "" {
		t.Error("Description should not be empty")
	}
}

func TestPrivescCheck_InvalidJSON(t *testing.T) {
	cmd := &PrivescCheckCommand{}
	task := structs.NewTask("test-1", "privesc-check", "not-json")
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Error("Expected error for invalid JSON")
	}
}

func TestPrivescCheck_UnknownAction(t *testing.T) {
	cmd := &PrivescCheckCommand{}
	task := structs.NewTask("test-1", "privesc-check", `{"action":"invalid"}`)
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Error("Expected error for unknown action")
	}
	if !strings.Contains(result.Output, "Unknown action") {
		t.Errorf("Expected 'Unknown action' in output, got: %s", result.Output)
	}
}

func TestPrivescCheck_DefaultsToAll(t *testing.T) {
	cmd := &PrivescCheckCommand{}
	task := structs.NewTask("test-1", "privesc-check", "")
	result := cmd.Execute(task)
	if result.Status != "success" {
		t.Errorf("Expected success, got: %s - %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "LINUX PRIVILEGE ESCALATION CHECK") {
		t.Error("Expected header in all-check output")
	}
}

func TestPrivescCheck_AllAction(t *testing.T) {
	cmd := &PrivescCheckCommand{}
	task := structs.NewTask("test-1", "privesc-check", `{"action":"all"}`)
	result := cmd.Execute(task)
	if result.Status != "success" {
		t.Errorf("Expected success, got: %s - %s", result.Status, result.Output)
	}
	// Should contain all sections
	if !strings.Contains(result.Output, "SUID/SGID") {
		t.Error("Missing SUID/SGID section in all output")
	}
	if !strings.Contains(result.Output, "Sudo") {
		t.Error("Missing Sudo section in all output")
	}
	if !strings.Contains(result.Output, "Container") {
		t.Error("Missing Container section in all output")
	}
}

func TestPrivescCheck_SuidAction(t *testing.T) {
	cmd := &PrivescCheckCommand{}
	task := structs.NewTask("test-1", "privesc-check", `{"action":"suid"}`)
	result := cmd.Execute(task)
	if result.Status != "success" {
		t.Errorf("Expected success, got: %s - %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "SUID binaries") {
		t.Error("Expected 'SUID binaries' in output")
	}
}

func TestPrivescCheck_CapabilitiesAction(t *testing.T) {
	cmd := &PrivescCheckCommand{}
	task := structs.NewTask("test-1", "privesc-check", `{"action":"capabilities"}`)
	result := cmd.Execute(task)
	if result.Status != "success" {
		t.Errorf("Expected success, got: %s - %s", result.Status, result.Output)
	}
	// Should at least have current process capabilities
	if !strings.Contains(result.Output, "Current process capabilities") {
		t.Error("Expected current process capabilities in output")
	}
}

func TestPrivescCheck_SudoAction(t *testing.T) {
	cmd := &PrivescCheckCommand{}
	task := structs.NewTask("test-1", "privesc-check", `{"action":"sudo"}`)
	result := cmd.Execute(task)
	if result.Status != "success" {
		t.Errorf("Expected success, got: %s - %s", result.Status, result.Output)
	}
}

func TestPrivescCheck_WritableAction(t *testing.T) {
	cmd := &PrivescCheckCommand{}
	task := structs.NewTask("test-1", "privesc-check", `{"action":"writable"}`)
	result := cmd.Execute(task)
	if result.Status != "success" {
		t.Errorf("Expected success, got: %s - %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "Writable PATH") {
		t.Error("Expected PATH check in output")
	}
}

func TestPrivescCheck_ContainerAction(t *testing.T) {
	cmd := &PrivescCheckCommand{}
	task := structs.NewTask("test-1", "privesc-check", `{"action":"container"}`)
	result := cmd.Execute(task)
	if result.Status != "success" {
		t.Errorf("Expected success, got: %s - %s", result.Status, result.Output)
	}
	// Should have hostname info
	if !strings.Contains(result.Output, "Hostname:") {
		t.Error("Expected hostname in container check output")
	}
}

func TestIsWritable(t *testing.T) {
	// /tmp should be writable
	if !isWritable("/tmp") {
		t.Error("Expected /tmp to be writable")
	}
	// /root should not be writable for non-root
	if os.Getuid() != 0 {
		if isWritable("/root") {
			t.Error("Expected /root to not be writable for non-root user")
		}
	}
}

func TestIsReadable(t *testing.T) {
	// /etc/passwd should be readable
	if !isReadable("/etc/passwd") {
		t.Error("Expected /etc/passwd to be readable")
	}
	// /etc/shadow should not be readable for non-root
	if os.Getuid() != 0 {
		if isReadable("/etc/shadow") {
			t.Error("Expected /etc/shadow to not be readable for non-root user")
		}
	}
}

func TestPrivescCheckPlainTextSuid(t *testing.T) {
	cmd := &PrivescCheckCommand{}
	result := cmd.Execute(structs.Task{Params: "suid"})
	if result.Status != "success" {
		t.Errorf("plain text 'suid' should succeed, got %s: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "SUID binaries") {
		t.Errorf("should contain SUID section")
	}
}

func TestPrivescCheckPlainTextCapabilities(t *testing.T) {
	cmd := &PrivescCheckCommand{}
	result := cmd.Execute(structs.Task{Params: "capabilities"})
	if result.Status != "success" {
		t.Errorf("plain text 'capabilities' should succeed, got %s: %s", result.Status, result.Output)
	}
}

func TestPrivescCheckPlainTextWritable(t *testing.T) {
	cmd := &PrivescCheckCommand{}
	result := cmd.Execute(structs.Task{Params: "writable"})
	if result.Status != "success" {
		t.Errorf("plain text 'writable' should succeed, got %s: %s", result.Status, result.Output)
	}
}
