//go:build windows
// +build windows

package commands

import (
	"encoding/json"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestNetUserNameAndDescription(t *testing.T) {
	cmd := &NetUserCommand{}
	if cmd.Name() != "net-user" {
		t.Errorf("Expected name 'net-user', got '%s'", cmd.Name())
	}
	if cmd.Description() == "" {
		t.Error("Description should not be empty")
	}
}

func TestNetUserEmptyParams(t *testing.T) {
	cmd := &NetUserCommand{}
	task := structs.Task{Params: ""}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Error("Expected error for empty params")
	}
	if !strings.Contains(result.Output, "parameters required") {
		t.Errorf("Expected parameters required error, got: %s", result.Output)
	}
}

func TestNetUserInvalidJSON(t *testing.T) {
	cmd := &NetUserCommand{}
	task := structs.Task{Params: "not json"}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Error("Expected error for invalid JSON")
	}
	if !strings.Contains(result.Output, "Error parsing parameters") {
		t.Errorf("Expected parsing error, got: %s", result.Output)
	}
}

func TestNetUserInvalidAction(t *testing.T) {
	cmd := &NetUserCommand{}
	params, _ := json.Marshal(map[string]string{"action": "invalid"})
	task := structs.Task{Params: string(params)}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Error("Expected error for invalid action")
	}
	if !strings.Contains(result.Output, "Unknown action") {
		t.Errorf("Expected unknown action error, got: %s", result.Output)
	}
}

func TestNetUserAddMissingUsername(t *testing.T) {
	cmd := &NetUserCommand{}
	params, _ := json.Marshal(map[string]string{"action": "add", "password": "Test123!"})
	task := structs.Task{Params: string(params)}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Error("Expected error for missing username")
	}
	if !strings.Contains(result.Output, "username is required") {
		t.Errorf("Expected username required error, got: %s", result.Output)
	}
}

func TestNetUserAddMissingPassword(t *testing.T) {
	cmd := &NetUserCommand{}
	params, _ := json.Marshal(map[string]string{"action": "add", "username": "testuser"})
	task := structs.Task{Params: string(params)}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Error("Expected error for missing password")
	}
	if !strings.Contains(result.Output, "password is required") {
		t.Errorf("Expected password required error, got: %s", result.Output)
	}
}

func TestNetUserDeleteMissingUsername(t *testing.T) {
	cmd := &NetUserCommand{}
	params, _ := json.Marshal(map[string]string{"action": "delete"})
	task := structs.Task{Params: string(params)}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Error("Expected error for missing username")
	}
	if !strings.Contains(result.Output, "username is required") {
		t.Errorf("Expected username required error, got: %s", result.Output)
	}
}

func TestNetUserInfoMissingUsername(t *testing.T) {
	cmd := &NetUserCommand{}
	params, _ := json.Marshal(map[string]string{"action": "info"})
	task := structs.Task{Params: string(params)}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Error("Expected error for missing username")
	}
	if !strings.Contains(result.Output, "username is required") {
		t.Errorf("Expected username required error, got: %s", result.Output)
	}
}

func TestNetUserPasswordMissingFields(t *testing.T) {
	cmd := &NetUserCommand{}

	// Missing username
	params, _ := json.Marshal(map[string]string{"action": "password", "password": "NewPass1!"})
	task := structs.Task{Params: string(params)}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Error("Expected error for missing username")
	}

	// Missing password
	params, _ = json.Marshal(map[string]string{"action": "password", "username": "testuser"})
	task = structs.Task{Params: string(params)}
	result = cmd.Execute(task)
	if result.Status != "error" {
		t.Error("Expected error for missing password")
	}
}

func TestNetUserGroupAddMissingFields(t *testing.T) {
	cmd := &NetUserCommand{}

	// Missing username
	params, _ := json.Marshal(map[string]string{"action": "group-add", "group": "Administrators"})
	task := structs.Task{Params: string(params)}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Error("Expected error for missing username")
	}

	// Missing group
	params, _ = json.Marshal(map[string]string{"action": "group-add", "username": "testuser"})
	task = structs.Task{Params: string(params)}
	result = cmd.Execute(task)
	if result.Status != "error" {
		t.Error("Expected error for missing group")
	}
}

func TestNetUserGroupRemoveMissingFields(t *testing.T) {
	cmd := &NetUserCommand{}

	// Missing username
	params, _ := json.Marshal(map[string]string{"action": "group-remove", "group": "Administrators"})
	task := structs.Task{Params: string(params)}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Error("Expected error for missing username")
	}

	// Missing group
	params, _ = json.Marshal(map[string]string{"action": "group-remove", "username": "testuser"})
	task = structs.Task{Params: string(params)}
	result = cmd.Execute(task)
	if result.Status != "error" {
		t.Error("Expected error for missing group")
	}
}

func TestNetUserInfoNonexistent(t *testing.T) {
	cmd := &NetUserCommand{}
	params, _ := json.Marshal(map[string]string{"action": "info", "username": "nonexistent_user_12345"})
	task := structs.Task{Params: string(params)}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Error("Expected error for nonexistent user")
	}
}

// TestNetUserLifecycle creates a user, queries info, changes password, adds to group, removes from group, then deletes.
// Requires admin privileges to run.
func TestNetUserLifecycle(t *testing.T) {
	cmd := &NetUserCommand{}
	testUser := "FawkesTestUser"
	testPass := "T3st!Pass#Fawkes99"

	// Create
	params, _ := json.Marshal(map[string]string{
		"action": "add", "username": testUser, "password": testPass,
		"comment": "Fawkes test account",
	})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Skipf("Cannot create user (need admin?): %s", result.Output)
	}
	if !strings.Contains(result.Output, "Successfully created") {
		t.Errorf("Expected creation message, got: %s", result.Output)
	}

	// Info
	params, _ = json.Marshal(map[string]string{"action": "info", "username": testUser})
	result = cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Errorf("Expected success for info, got: %s — %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, testUser) {
		t.Errorf("Expected username in output, got: %s", result.Output)
	}
	if !strings.Contains(result.Output, "Fawkes test account") {
		t.Errorf("Expected comment in output, got: %s", result.Output)
	}

	// Password change
	params, _ = json.Marshal(map[string]string{"action": "password", "username": testUser, "password": "N3w!Pass#Fawkes88"})
	result = cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Errorf("Expected success for password change, got: %s — %s", result.Status, result.Output)
	}

	// Group add
	params, _ = json.Marshal(map[string]string{"action": "group-add", "username": testUser, "group": "Users"})
	result = cmd.Execute(structs.Task{Params: string(params)})
	// Users group: new users are already members, so this might succeed or fail with 1378 (already member)
	// Both are acceptable

	// Group remove
	params, _ = json.Marshal(map[string]string{"action": "group-remove", "username": testUser, "group": "Users"})
	result = cmd.Execute(structs.Task{Params: string(params)})
	// Acceptable to fail if not a member

	// Delete
	params, _ = json.Marshal(map[string]string{"action": "delete", "username": testUser})
	result = cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Errorf("Expected success for delete, got: %s — %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "Successfully deleted") {
		t.Errorf("Expected deletion message, got: %s", result.Output)
	}

	// Verify deletion - info should fail
	params, _ = json.Marshal(map[string]string{"action": "info", "username": testUser})
	result = cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Error("Expected error for deleted user info query")
	}
}
