//go:build linux

package commands

import (
	"encoding/json"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

// Helper function tests (extractCgroupPath, cleanDockerLogs, parseCapEff, etc.)
// are in container_escape_helpers_test.go (cross-platform, no build tags).

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

