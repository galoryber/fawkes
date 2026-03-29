package commands

import (
	"os"
	"testing"
)

func TestPwdCommandName(t *testing.T) {
	assertCommandName(t, &PwdCommand{}, "pwd")
}

func TestPwdCommandDescription(t *testing.T) {
	assertCommandHasDescription(t, &PwdCommand{})
}

func TestPwdReturnsCurrentDir(t *testing.T) {
	cmd := &PwdCommand{}
	result := cmd.Execute(mockTask("pwd", ""))
	assertSuccess(t, result)

	expected, _ := os.Getwd()
	if result.Output != expected {
		t.Errorf("expected %q, got %q", expected, result.Output)
	}
}
