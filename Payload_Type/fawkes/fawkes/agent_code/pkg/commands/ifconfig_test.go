package commands

import (
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestIfconfigName(t *testing.T) {
	cmd := &IfconfigCommand{}
	if cmd.Name() != "ifconfig" {
		t.Errorf("expected 'ifconfig', got %q", cmd.Name())
	}
}

func TestIfconfigDescription(t *testing.T) {
	cmd := &IfconfigCommand{}
	if cmd.Description() == "" {
		t.Error("description should not be empty")
	}
}

func TestIfconfigExecuteDefault(t *testing.T) {
	cmd := &IfconfigCommand{}
	task := structs.NewTask("t", "ifconfig", "")
	result := cmd.Execute(task)
	if result.Status != "success" {
		t.Fatalf("expected success, got %q: %s", result.Status, result.Output)
	}
	if !result.Completed {
		t.Error("expected Completed=true")
	}
	// Every Linux system has a loopback interface
	if !strings.Contains(result.Output, "lo") {
		t.Errorf("expected output to contain 'lo' (loopback interface), got: %s", result.Output)
	}
}

func TestIfconfigExecuteContainsIP(t *testing.T) {
	cmd := &IfconfigCommand{}
	task := structs.NewTask("t", "ifconfig", "")
	result := cmd.Execute(task)
	if result.Status != "success" {
		t.Fatalf("expected success, got %q: %s", result.Status, result.Output)
	}
	// The loopback interface at minimum has 127.0.0.1 (inet) or ::1 (inet6)
	hasInet := strings.Contains(result.Output, "inet ")
	hasInet6 := strings.Contains(result.Output, "inet6 ")
	if !hasInet && !hasInet6 {
		t.Errorf("expected output to contain 'inet' or 'inet6', got: %s", result.Output)
	}
}
