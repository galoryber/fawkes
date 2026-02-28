package commands

import (
	"os"
	"testing"

	"fawkes/pkg/structs"
)

func TestPwdCommandName(t *testing.T) {
	cmd := &PwdCommand{}
	if cmd.Name() != "pwd" {
		t.Errorf("expected 'pwd', got %q", cmd.Name())
	}
}

func TestPwdCommandDescription(t *testing.T) {
	cmd := &PwdCommand{}
	if cmd.Description() == "" {
		t.Error("description should not be empty")
	}
}

func TestPwdReturnsCurrentDir(t *testing.T) {
	cmd := &PwdCommand{}
	task := structs.NewTask("t", "pwd", "")
	result := cmd.Execute(task)
	if result.Status != "success" {
		t.Errorf("expected success, got %q: %s", result.Status, result.Output)
	}

	expected, _ := os.Getwd()
	if result.Output != expected {
		t.Errorf("expected %q, got %q", expected, result.Output)
	}
}
