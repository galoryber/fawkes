package commands

import (
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestContainerDetectName(t *testing.T) {
	cmd := &ContainerDetectCommand{}
	if cmd.Name() != "container-detect" {
		t.Errorf("Name() = %q, want %q", cmd.Name(), "container-detect")
	}
}

func TestContainerDetectDescription(t *testing.T) {
	cmd := &ContainerDetectCommand{}
	if cmd.Description() == "" {
		t.Error("Description() should not be empty")
	}
}

func TestContainerDetectExecute(t *testing.T) {
	cmd := &ContainerDetectCommand{}
	task := structs.Task{Params: ""}
	result := cmd.Execute(task)
	if result.Status != "success" {
		t.Errorf("Status = %q, want %q", result.Status, "success")
	}
	if !result.Completed {
		t.Error("Completed should be true")
	}
	if !strings.Contains(result.Output, "Container/Environment Detection") {
		t.Error("Output should contain detection header")
	}
}

func TestContainerDetectLinux(t *testing.T) {
	evidence, detected := containerDetectLinux()
	// Should return some evidence regardless
	if len(evidence) == 0 {
		t.Error("Should return at least one piece of evidence")
	}
	// detected should be a string (possibly "none")
	_ = detected
}

func TestContainerDetectOutputFormat(t *testing.T) {
	cmd := &ContainerDetectCommand{}
	task := structs.Task{Params: ""}
	result := cmd.Execute(task)

	// Should have table header
	if !strings.Contains(result.Output, "Check") && !strings.Contains(result.Output, "Result") {
		t.Error("Output should contain table headers")
	}
}
