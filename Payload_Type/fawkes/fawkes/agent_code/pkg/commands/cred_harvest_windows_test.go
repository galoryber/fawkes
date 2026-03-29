//go:build windows
// +build windows

package commands

import (
	"testing"

	"fawkes/pkg/structs"
)

func TestCredHarvestDispatch_Windows_ValidActions(t *testing.T) {
	validActions := []string{"cloud", "configs", "windows", "m365-tokens", "history", "all"}
	for _, action := range validActions {
		t.Run(action, func(t *testing.T) {
			args := credHarvestArgs{Action: action}
			result := credHarvestDispatch(args)
			// The command runs on the actual system; verify it doesn't error on action routing
			if result.Status == "error" && result.Output != "" {
				if len(result.Output) > 15 && result.Output[:15] == "Unknown action:" {
					t.Errorf("action %q should be valid", action)
				}
			}
		})
	}
}

func TestCredHarvestDispatch_Windows_InvalidAction(t *testing.T) {
	args := credHarvestArgs{Action: "invalid"}
	result := credHarvestDispatch(args)
	if result.Status != "error" {
		t.Errorf("expected error for invalid action, got %q", result.Status)
	}
}

func TestCredHarvestDispatch_Windows_CaseInsensitive(t *testing.T) {
	tests := []string{"CLOUD", "Cloud", "WINDOWS", "Windows", "ALL", "All"}
	for _, action := range tests {
		args := credHarvestArgs{Action: action}
		result := credHarvestDispatch(args)
		if result.Status == "error" && result.Output != "" {
			if len(result.Output) > 15 && result.Output[:15] == "Unknown action:" {
				t.Errorf("action %q should be case-insensitive", action)
			}
		}
	}
}

func TestCredHarvestCommand_Execute_EmptyParams(t *testing.T) {
	cmd := &CredHarvestCommand{}
	task := structs.Task{Params: ""}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Errorf("expected error for empty params, got %q", result.Status)
	}
}

func TestCredHarvestCommand_Execute_InvalidJSON(t *testing.T) {
	cmd := &CredHarvestCommand{}
	task := structs.Task{Params: "{bad"}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Errorf("expected error for invalid JSON, got %q", result.Status)
	}
}

func TestGetUserHomes_FilterEmpty(t *testing.T) {
	// With no filter, should return at least the current user's home
	homes := getUserHomes("")
	if len(homes) == 0 {
		t.Skip("no home directories found (may be running in CI without standard passwd)")
	}
	for _, home := range homes {
		if home == "" || home == "/" || home == "/nonexistent" || home == "/dev/null" {
			t.Errorf("filtered directory should not appear: %q", home)
		}
	}
}

func TestGetUserHomes_FilterNonexistent(t *testing.T) {
	// Filter for a user that doesn't exist should return empty
	homes := getUserHomes("zzz_nonexistent_user_xyz")
	if len(homes) != 0 {
		t.Errorf("expected 0 homes for nonexistent user filter, got %d", len(homes))
	}
}
