package commands

import "testing"

func TestExitName(t *testing.T) {
	cmd := &ExitCommand{}
	if cmd.Name() != "exit" {
		t.Errorf("expected 'exit', got '%s'", cmd.Name())
	}
}

func TestExitDescription(t *testing.T) {
	cmd := &ExitCommand{}
	if cmd.Description() == "" {
		t.Error("description should not be empty")
	}
}
