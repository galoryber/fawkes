//go:build linux

package commands

import (
	"encoding/json"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestContainerEscapeName(t *testing.T) {
	cmd := &ContainerEscapeCommand{}
	if cmd.Name() != "container-escape" {
		t.Errorf("Expected 'container-escape', got '%s'", cmd.Name())
	}
}

func TestContainerEscapeDescription(t *testing.T) {
	cmd := &ContainerEscapeCommand{}
	if cmd.Description() == "" {
		t.Error("Description should not be empty")
	}
}

func TestContainerEscapeBadJSON(t *testing.T) {
	cmd := &ContainerEscapeCommand{}
	result := cmd.Execute(structs.Task{Params: "not json"})
	if result.Status != "error" {
		t.Error("Expected error for bad JSON")
	}
}

func TestContainerEscapeUnknownAction(t *testing.T) {
	cmd := &ContainerEscapeCommand{}
	params, _ := json.Marshal(containerEscapeArgs{Action: "badaction"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Error("Expected error for unknown action")
	}
	if !strings.Contains(result.Output, "Unknown action") {
		t.Errorf("Expected unknown action error, got: %s", result.Output)
	}
}

func TestContainerEscapeCheck(t *testing.T) {
	cmd := &ContainerEscapeCommand{}
	params, _ := json.Marshal(containerEscapeArgs{Action: "check"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Errorf("Expected success for check, got %s: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "CONTAINER ESCAPE VECTOR CHECK") {
		t.Errorf("Expected check header, got: %s", result.Output)
	}
	if !strings.Contains(result.Output, "escape vector(s) identified") {
		t.Errorf("Expected summary, got: %s", result.Output)
	}
}

func TestContainerEscapeDefaultAction(t *testing.T) {
	cmd := &ContainerEscapeCommand{}
	params, _ := json.Marshal(containerEscapeArgs{})
	result := cmd.Execute(structs.Task{Params: string(params)})
	// Default action is "check"
	if result.Status != "success" {
		t.Errorf("Expected success for default action, got %s: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "CONTAINER ESCAPE VECTOR CHECK") {
		t.Errorf("Expected check header for default action, got: %s", result.Output)
	}
}

func TestContainerEscapeDockerSockMissingCommand(t *testing.T) {
	cmd := &ContainerEscapeCommand{}
	params, _ := json.Marshal(containerEscapeArgs{Action: "docker-sock"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Error("Expected error for docker-sock without command")
	}
	if !strings.Contains(result.Output, "Required: -command") {
		t.Errorf("Expected required command error, got: %s", result.Output)
	}
}

func TestContainerEscapeCgroupMissingCommand(t *testing.T) {
	cmd := &ContainerEscapeCommand{}
	params, _ := json.Marshal(containerEscapeArgs{Action: "cgroup"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Error("Expected error for cgroup without command")
	}
	if !strings.Contains(result.Output, "Required: -command") {
		t.Errorf("Expected required command error, got: %s", result.Output)
	}
}

func TestContainerEscapeNsenterMissingCommand(t *testing.T) {
	cmd := &ContainerEscapeCommand{}
	params, _ := json.Marshal(containerEscapeArgs{Action: "nsenter"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Error("Expected error for nsenter without command")
	}
	if !strings.Contains(result.Output, "Required: -command") {
		t.Errorf("Expected required command error, got: %s", result.Output)
	}
}

// --- Helper function tests ---

func TestExtractCgroupPath(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"", ""},
		{"12:memory:/docker/abc123\n", "/docker/abc123"},
		{"0::/\n", ""},
		{"12:memory:/\n0::/system.slice/docker-abc.scope\n", "/system.slice/docker-abc.scope"},
		{"invalid line\n", ""},
	}

	for _, tc := range tests {
		result := extractCgroupPath(tc.input)
		if result != tc.expected {
			t.Errorf("extractCgroupPath(%q) = %q, want %q", tc.input, result, tc.expected)
		}
	}
}

func TestCleanDockerLogs(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		contains string
	}{
		{"normal line", "\x01\x00\x00\x00\x00\x00\x00\x05hello", "hello"},
		{"short line", "short", "short"},
		{"empty", "", ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := cleanDockerLogs(tc.input)
			if tc.contains != "" && !strings.Contains(result, tc.contains) {
				t.Errorf("Expected %q in result, got: %q", tc.contains, result)
			}
		})
	}
}
