package commands

import (
	"encoding/json"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

// =============================================================================
// Registry tests
// =============================================================================

func TestInitialize(t *testing.T) {
	// Initialize should register all commands without panicking
	Initialize()

	// Verify cross-platform commands are registered
	crossPlatformCmds := []string{
		"cat", "cd", "cp", "download", "ls", "mkdir", "mv", "ps", "pwd",
		"rm", "run", "sleep", "socks", "upload", "env", "exit", "kill",
		"whoami", "ifconfig", "find", "net-stat", "port-scan", "timestomp", "arp",
	}
	for _, name := range crossPlatformCmds {
		cmd := GetCommand(name)
		if cmd == nil {
			t.Errorf("GetCommand(%q) = nil after Initialize", name)
		}
	}

	// On Linux, crontab and ssh-keys should also be registered
	linuxCmds := []string{"crontab", "ssh-keys"}
	for _, name := range linuxCmds {
		cmd := GetCommand(name)
		if cmd == nil {
			t.Errorf("GetCommand(%q) = nil after Initialize (expected on Linux)", name)
		}
	}
}

func TestRegisterCommand(t *testing.T) {
	// Register a mock command
	mock := &mockCommand{name: "test-register-cmd"}
	RegisterCommand(mock)

	retrieved := GetCommand("test-register-cmd")
	if retrieved == nil {
		t.Fatal("GetCommand returned nil for registered command")
	}
	if retrieved.Name() != "test-register-cmd" {
		t.Errorf("Name() = %q, want %q", retrieved.Name(), "test-register-cmd")
	}
}

func TestGetCommand_NotFound(t *testing.T) {
	cmd := GetCommand("nonexistent-command-xyz")
	if cmd != nil {
		t.Errorf("GetCommand for nonexistent command should return nil, got %v", cmd)
	}
}

func TestGetAllCommands(t *testing.T) {
	Initialize()

	all := GetAllCommands()
	if len(all) == 0 {
		t.Fatal("GetAllCommands returned empty map")
	}

	// Should have at least the 24 cross-platform commands + 2 Linux commands
	if len(all) < 26 {
		t.Errorf("GetAllCommands returned %d commands, expected at least 26", len(all))
	}

	// Verify the returned map is a copy (not the original)
	all["injected-test"] = &mockCommand{name: "injected-test"}
	original := GetCommand("injected-test")
	if original != nil {
		t.Error("GetAllCommands should return a copy, not the original map")
	}
}

// mockCommand is a minimal Command for testing registration
type mockCommand struct {
	name string
}

func (m *mockCommand) Name() string        { return m.name }
func (m *mockCommand) Description() string { return "mock command for testing" }
func (m *mockCommand) Execute(task structs.Task) structs.CommandResult {
	return structs.CommandResult{Output: "mock", Status: "success", Completed: true}
}

// =============================================================================
// Description() coverage — verify all commands have non-empty descriptions
// =============================================================================

func TestAllCommandDescriptions(t *testing.T) {
	Initialize()

	all := GetAllCommands()
	for name, cmd := range all {
		t.Run(name, func(t *testing.T) {
			desc := cmd.Description()
			if desc == "" {
				t.Errorf("command %q has empty Description()", name)
			}
		})
	}
}

// =============================================================================
// netstat Execute test (calls gopsutil which works on Linux)
// =============================================================================

func TestNetstatCommand_Execute(t *testing.T) {
	cmd := &NetstatCommand{}

	task := structs.Task{Params: ""}
	result := cmd.Execute(task)

	// On any Linux system, there should be at least some connections
	if result.Status != "success" {
		t.Errorf("expected success, got %q: %s", result.Status, result.Output)
	}

	// Output should contain header
	if !strings.Contains(result.Output, "Proto") {
		t.Errorf("output should contain Proto header, got: %s", result.Output[:min(200, len(result.Output))])
	}
	if !strings.Contains(result.Output, "Local Address") {
		t.Errorf("output should contain Local Address header, got: %s", result.Output[:min(200, len(result.Output))])
	}

	// Should have at least 1 connection
	if !strings.Contains(result.Output, "connections") {
		t.Errorf("output should contain connection count, got: %s", result.Output[:min(200, len(result.Output))])
	}
}

// =============================================================================
// arp Execute test (calls ip neigh on Linux)
// =============================================================================

func TestArpCommand_Execute(t *testing.T) {
	cmd := &ArpCommand{}

	task := structs.Task{Params: ""}
	result := cmd.Execute(task)

	// Should succeed on most Linux systems
	if result.Status != "success" {
		t.Logf("arp command returned %q (may be expected if ip/arp not available): %s",
			result.Status, result.Output)
		return
	}
	if !result.Completed {
		t.Error("expected Completed=true")
	}
}

// =============================================================================
// exit command test (verifies response, can't test os.Exit)
// =============================================================================

func TestExitCommand_Name(t *testing.T) {
	cmd := &ExitCommand{}
	if cmd.Name() != "exit" {
		t.Errorf("Name() = %q, want %q", cmd.Name(), "exit")
	}
	if cmd.Description() == "" {
		t.Error("Description() should not be empty")
	}
}

// =============================================================================
// crontab command parameter parsing tests
// =============================================================================

func TestCrontabCommand_Name(t *testing.T) {
	cmd := &CrontabCommand{}
	if cmd.Name() != "crontab" {
		t.Errorf("Name() = %q, want %q", cmd.Name(), "crontab")
	}
	if cmd.Description() == "" {
		t.Error("Description() should not be empty")
	}
}

func TestCrontabCommand_EmptyParams(t *testing.T) {
	cmd := &CrontabCommand{}
	task := structs.Task{Params: ""}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Errorf("expected error for empty params, got %q", result.Status)
	}
}

func TestCrontabCommand_InvalidJSON(t *testing.T) {
	cmd := &CrontabCommand{}
	task := structs.Task{Params: "not json"}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Errorf("expected error for invalid JSON, got %q", result.Status)
	}
}

func TestCrontabCommand_UnknownAction(t *testing.T) {
	cmd := &CrontabCommand{}
	params, _ := json.Marshal(map[string]string{"action": "restart"})
	task := structs.Task{Params: string(params)}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Errorf("expected error for unknown action, got %q", result.Status)
	}
	if !strings.Contains(result.Output, "restart") {
		t.Errorf("error should mention the bad action, got: %s", result.Output)
	}
}

func TestCrontabCommand_ListAction(t *testing.T) {
	cmd := &CrontabCommand{}
	params, _ := json.Marshal(map[string]string{"action": "list"})
	task := structs.Task{Params: string(params)}
	result := cmd.Execute(task)

	// Should succeed even if no crontab exists
	if result.Status != "success" && result.Status != "error" {
		t.Errorf("unexpected status %q: %s", result.Status, result.Output)
	}
}

func TestCrontabCommand_AddMissingProgram(t *testing.T) {
	cmd := &CrontabCommand{}
	params, _ := json.Marshal(map[string]string{"action": "add"})
	task := structs.Task{Params: string(params)}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Errorf("expected error for add without entry/program, got %q", result.Status)
	}
}

func TestCrontabCommand_RemoveMissingEntry(t *testing.T) {
	cmd := &CrontabCommand{}
	params, _ := json.Marshal(map[string]string{"action": "remove"})
	task := structs.Task{Params: string(params)}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Errorf("expected error for remove without entry/program, got %q", result.Status)
	}
}

// =============================================================================
// ssh-keys command parameter parsing tests
// =============================================================================

func TestSSHKeysCommand_Name(t *testing.T) {
	cmd := &SSHKeysCommand{}
	if cmd.Name() != "ssh-keys" {
		t.Errorf("Name() = %q, want %q", cmd.Name(), "ssh-keys")
	}
	if cmd.Description() == "" {
		t.Error("Description() should not be empty")
	}
}

func TestSSHKeysCommand_EmptyParams(t *testing.T) {
	cmd := &SSHKeysCommand{}
	task := structs.Task{Params: ""}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Errorf("expected error for empty params, got %q", result.Status)
	}
}

func TestSSHKeysCommand_InvalidJSON(t *testing.T) {
	cmd := &SSHKeysCommand{}
	task := structs.Task{Params: "not json"}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Errorf("expected error for invalid JSON, got %q", result.Status)
	}
}

func TestSSHKeysCommand_UnknownAction(t *testing.T) {
	cmd := &SSHKeysCommand{}
	params, _ := json.Marshal(map[string]string{"action": "delete"})
	task := structs.Task{Params: string(params)}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Errorf("expected error for unknown action, got %q", result.Status)
	}
	if !strings.Contains(result.Output, "delete") {
		t.Errorf("error should mention the bad action, got: %s", result.Output)
	}
}

func TestSSHKeysCommand_ListAction(t *testing.T) {
	cmd := &SSHKeysCommand{}
	params, _ := json.Marshal(map[string]string{"action": "list"})
	task := structs.Task{Params: string(params)}
	result := cmd.Execute(task)

	// Should succeed or error gracefully depending on whether .ssh exists
	if !result.Completed {
		t.Error("expected Completed=true")
	}
}

