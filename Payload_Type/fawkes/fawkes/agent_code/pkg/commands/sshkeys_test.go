//go:build !windows

package commands

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestSshKeysName(t *testing.T) {
	cmd := &SSHKeysCommand{}
	if cmd.Name() != "ssh-keys" {
		t.Errorf("expected 'ssh-keys', got %q", cmd.Name())
	}
}

func TestSshKeysDescription(t *testing.T) {
	cmd := &SSHKeysCommand{}
	if cmd.Description() == "" {
		t.Error("description should not be empty")
	}
}

func TestSshKeysExecuteDefault(t *testing.T) {
	cmd := &SSHKeysCommand{}
	// Action "read-private" with no custom path searches default ~/.ssh paths
	params, _ := json.Marshal(sshKeysArgs{
		Action: "read-private",
	})
	task := structs.NewTask("t", "ssh-keys", "")
	task.Params = string(params)
	result := cmd.Execute(task)

	// Should succeed — either finds keys or reports "No private keys found"
	if result.Status != "success" && result.Status != "error" {
		t.Fatalf("unexpected status %q: %s", result.Status, result.Output)
	}
	if !result.Completed {
		t.Error("expected Completed=true")
	}
}

func TestSshKeysExecuteCustomPath(t *testing.T) {
	// Create a temp directory to use as a custom path for authorized_keys
	tmp := t.TempDir()
	authKeysPath := filepath.Join(tmp, "authorized_keys")
	// Create an empty authorized_keys file
	os.WriteFile(authKeysPath, []byte(""), 0600)

	cmd := &SSHKeysCommand{}
	params, _ := json.Marshal(sshKeysArgs{
		Action: "list",
		Path:   authKeysPath,
	})
	task := structs.NewTask("t", "ssh-keys", "")
	task.Params = string(params)
	result := cmd.Execute(task)

	if result.Status != "success" {
		t.Fatalf("expected success, got %q: %s", result.Status, result.Output)
	}
	// With an empty file, should report 0 keys
	if !strings.Contains(result.Output, "0 key(s)") && !strings.Contains(result.Output, "(empty file)") {
		t.Errorf("expected output to indicate 0 keys or empty file, got: %s", result.Output)
	}
}
