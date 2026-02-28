//go:build !windows

package commands

import (
	"os/user"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestWhoamiCommandName(t *testing.T) {
	cmd := &WhoamiCommand{}
	if cmd.Name() != "whoami" {
		t.Errorf("expected 'whoami', got %q", cmd.Name())
	}
}

func TestWhoamiCommandDescription(t *testing.T) {
	cmd := &WhoamiCommand{}
	if cmd.Description() == "" {
		t.Error("description should not be empty")
	}
}

func TestWhoamiReturnsUser(t *testing.T) {
	cmd := &WhoamiCommand{}
	task := structs.NewTask("t", "whoami", "")
	result := cmd.Execute(task)
	if result.Status != "success" {
		t.Errorf("expected success, got %q: %s", result.Status, result.Output)
	}

	u, _ := user.Current()
	if !strings.Contains(result.Output, u.Username) {
		t.Errorf("output should contain username %q, got %q", u.Username, result.Output)
	}
	if !strings.Contains(result.Output, u.Uid) {
		t.Errorf("output should contain UID %q", u.Uid)
	}
}

func TestWhoamiShowsGroups(t *testing.T) {
	cmd := &WhoamiCommand{}
	task := structs.NewTask("t", "whoami", "")
	result := cmd.Execute(task)
	if result.Status != "success" {
		t.Fatalf("expected success, got %q", result.Status)
	}
	if !strings.Contains(result.Output, "Groups:") {
		t.Error("output should contain Groups section")
	}
}
