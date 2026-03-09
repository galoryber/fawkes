//go:build linux

package commands

import (
	"encoding/json"
	"os/user"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestNetUserLinuxNameAndDescription(t *testing.T) {
	cmd := &NetUserCommand{}
	if cmd.Name() != "net-user" {
		t.Errorf("Expected name 'net-user', got '%s'", cmd.Name())
	}
	if cmd.Description() == "" {
		t.Error("Description should not be empty")
	}
}

func TestNetUserLinuxEmptyParams(t *testing.T) {
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

func TestNetUserLinuxInvalidJSON(t *testing.T) {
	cmd := &NetUserCommand{}
	task := structs.Task{Params: "not json"}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Error("Expected error for invalid JSON")
	}
}

func TestNetUserLinuxInvalidAction(t *testing.T) {
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

func TestNetUserLinuxAddMissingUsername(t *testing.T) {
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

func TestNetUserLinuxAddMissingPassword(t *testing.T) {
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

func TestNetUserLinuxDeleteMissingUsername(t *testing.T) {
	cmd := &NetUserCommand{}
	params, _ := json.Marshal(map[string]string{"action": "delete"})
	task := structs.Task{Params: string(params)}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Error("Expected error for missing username")
	}
}

func TestNetUserLinuxInfoMissingUsername(t *testing.T) {
	cmd := &NetUserCommand{}
	params, _ := json.Marshal(map[string]string{"action": "info"})
	task := structs.Task{Params: string(params)}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Error("Expected error for missing username")
	}
}

func TestNetUserLinuxPasswordMissingFields(t *testing.T) {
	cmd := &NetUserCommand{}

	// Missing username
	params, _ := json.Marshal(map[string]string{"action": "password", "password": "NewPass1!"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Error("Expected error for missing username")
	}

	// Missing password
	params, _ = json.Marshal(map[string]string{"action": "password", "username": "testuser"})
	result = cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Error("Expected error for missing password")
	}
}

func TestNetUserLinuxGroupAddMissingFields(t *testing.T) {
	cmd := &NetUserCommand{}

	// Missing username
	params, _ := json.Marshal(map[string]string{"action": "group-add", "group": "sudo"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Error("Expected error for missing username")
	}

	// Missing group
	params, _ = json.Marshal(map[string]string{"action": "group-add", "username": "testuser"})
	result = cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Error("Expected error for missing group")
	}
}

func TestNetUserLinuxGroupRemoveMissingFields(t *testing.T) {
	cmd := &NetUserCommand{}

	// Missing username
	params, _ := json.Marshal(map[string]string{"action": "group-remove", "group": "sudo"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Error("Expected error for missing username")
	}

	// Missing group
	params, _ = json.Marshal(map[string]string{"action": "group-remove", "username": "testuser"})
	result = cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Error("Expected error for missing group")
	}
}

func TestNetUserLinuxInfoCurrentUser(t *testing.T) {
	u, err := user.Current()
	if err != nil {
		t.Skip("Cannot get current user")
	}

	cmd := &NetUserCommand{}
	params, _ := json.Marshal(map[string]string{"action": "info", "username": u.Username})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Errorf("Expected success for current user info, got: %s — %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, u.Username) {
		t.Errorf("Expected username in output, got: %s", result.Output)
	}
	if !strings.Contains(result.Output, "UID:") {
		t.Errorf("Expected UID in output, got: %s", result.Output)
	}
	if !strings.Contains(result.Output, "Shell:") {
		t.Errorf("Expected Shell in output, got: %s", result.Output)
	}
}

func TestNetUserLinuxInfoNonexistent(t *testing.T) {
	cmd := &NetUserCommand{}
	params, _ := json.Marshal(map[string]string{"action": "info", "username": "nonexistent_user_12345"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Error("Expected error for nonexistent user")
	}
	if !strings.Contains(result.Output, "not found") {
		t.Errorf("Expected not found error, got: %s", result.Output)
	}
}
