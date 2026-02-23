//go:build linux
// +build linux

package commands

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestSystemdPersistName(t *testing.T) {
	cmd := &SystemdPersistCommand{}
	if cmd.Name() != "systemd-persist" {
		t.Errorf("expected systemd-persist, got %s", cmd.Name())
	}
}

func TestSystemdPersistEmptyParams(t *testing.T) {
	cmd := &SystemdPersistCommand{}
	result := cmd.Execute(structs.Task{Params: ""})
	if result.Status != "error" {
		t.Error("empty params should return error")
	}
}

func TestSystemdPersistBadJSON(t *testing.T) {
	cmd := &SystemdPersistCommand{}
	result := cmd.Execute(structs.Task{Params: "not json"})
	if result.Status != "error" {
		t.Error("bad JSON should return error")
	}
}

func TestSystemdPersistInvalidAction(t *testing.T) {
	cmd := &SystemdPersistCommand{}
	result := cmd.Execute(structs.Task{Params: `{"action":"badaction"}`})
	if result.Status != "error" {
		t.Error("invalid action should return error")
	}
}

func TestSystemdPersistInstallMissingName(t *testing.T) {
	cmd := &SystemdPersistCommand{}
	result := cmd.Execute(structs.Task{Params: `{"action":"install","exec_start":"/tmp/payload"}`})
	if result.Status != "error" {
		t.Error("install without name should return error")
	}
}

func TestSystemdPersistInstallMissingExecStart(t *testing.T) {
	cmd := &SystemdPersistCommand{}
	result := cmd.Execute(structs.Task{Params: `{"action":"install","name":"test"}`})
	if result.Status != "error" {
		t.Error("install without exec_start should return error")
	}
}

func TestSystemdPersistRemoveMissingName(t *testing.T) {
	cmd := &SystemdPersistCommand{}
	result := cmd.Execute(structs.Task{Params: `{"action":"remove"}`})
	if result.Status != "error" {
		t.Error("remove without name should return error")
	}
}

func TestSystemdPersistInstallAndRemove(t *testing.T) {
	// Use a temp dir to simulate user systemd dir
	tmpDir := t.TempDir()

	// Manually test the unit file generation by creating a service
	cmd := &SystemdPersistCommand{}

	// Test install to user dir (will use real home dir)
	result := cmd.Execute(structs.Task{Params: `{"action":"install","name":"test_fawkes","exec_start":"/tmp/test_payload"}`})
	if result.Status != "success" {
		t.Fatalf("install should succeed: %s", result.Output)
	}
	if !strings.Contains(result.Output, "test_fawkes.service") {
		t.Error("output should mention service name")
	}
	if !strings.Contains(result.Output, "/tmp/test_payload") {
		t.Error("output should mention exec_start")
	}

	// Cleanup the file we created
	home, _ := os.UserHomeDir()
	servicePath := filepath.Join(home, ".config", "systemd", "user", "test_fawkes.service")
	defer os.Remove(servicePath)

	// Verify file was created
	content, err := os.ReadFile(servicePath)
	if err != nil {
		t.Fatalf("service file should exist: %v", err)
	}
	if !strings.Contains(string(content), "ExecStart=/tmp/test_payload") {
		t.Error("service file should contain ExecStart")
	}
	if !strings.Contains(string(content), "WantedBy=default.target") {
		t.Error("user service should want default.target")
	}

	// Test remove
	result = cmd.Execute(structs.Task{Params: `{"action":"remove","name":"test_fawkes"}`})
	if result.Status != "success" {
		t.Fatalf("remove should succeed: %s", result.Output)
	}

	// Verify file was removed
	if _, err := os.Stat(servicePath); !os.IsNotExist(err) {
		t.Error("service file should be removed")
	}

	_ = tmpDir // used for cleanup reference
}

func TestSystemdPersistList(t *testing.T) {
	cmd := &SystemdPersistCommand{}
	result := cmd.Execute(structs.Task{Params: `{"action":"list"}`})
	if result.Status != "success" {
		t.Fatalf("list should succeed: %s", result.Output)
	}
	if !strings.Contains(result.Output, "User Services") {
		t.Error("list should include user services section")
	}
	if !strings.Contains(result.Output, "System Services") {
		t.Error("list should include system services section")
	}
}

func TestExtractField(t *testing.T) {
	content := "[Unit]\nDescription=Test Service\n\n[Service]\nExecStart=/usr/bin/test\n"
	if extractField(content, "Description=") != "Test Service" {
		t.Error("should extract Description")
	}
	if extractField(content, "ExecStart=") != "/usr/bin/test" {
		t.Error("should extract ExecStart")
	}
	if extractField(content, "NonExistent=") != "" {
		t.Error("missing field should return empty string")
	}
}

func TestSystemdPersistInstallWithTimer(t *testing.T) {
	cmd := &SystemdPersistCommand{}
	result := cmd.Execute(structs.Task{Params: `{"action":"install","name":"test_timer","exec_start":"/tmp/payload","timer":"*-*-* *:00/5:00"}`})
	if result.Status != "success" {
		t.Fatalf("install with timer should succeed: %s", result.Output)
	}
	if !strings.Contains(result.Output, "Timer") {
		t.Error("output should mention timer")
	}

	// Cleanup
	home, _ := os.UserHomeDir()
	os.Remove(filepath.Join(home, ".config", "systemd", "user", "test_timer.service"))
	os.Remove(filepath.Join(home, ".config", "systemd", "user", "test_timer.timer"))
}
