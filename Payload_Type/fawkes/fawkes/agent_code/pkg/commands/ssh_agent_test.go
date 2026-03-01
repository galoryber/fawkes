//go:build !windows

package commands

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"fawkes/pkg/structs"

	"golang.org/x/crypto/ssh/agent"
)

func TestSSHAgentCommandName(t *testing.T) {
	cmd := &SSHAgentCommand{}
	if cmd.Name() != "ssh-agent" {
		t.Errorf("expected 'ssh-agent', got %q", cmd.Name())
	}
}

func TestSSHAgentCommandDescription(t *testing.T) {
	cmd := &SSHAgentCommand{}
	if cmd.Description() == "" {
		t.Error("description should not be empty")
	}
}

func TestSSHAgentEnumNoSockets(t *testing.T) {
	// With SSH_AUTH_SOCK unset and no sockets in /tmp, enum should return empty
	origSock := os.Getenv("SSH_AUTH_SOCK")
	os.Unsetenv("SSH_AUTH_SOCK")
	defer func() {
		if origSock != "" {
			os.Setenv("SSH_AUTH_SOCK", origSock)
		}
	}()

	result := sshAgentEnum()
	if result.Status != "success" {
		t.Errorf("expected success, got %q", result.Status)
	}
}

func TestSSHAgentListInvalidSocket(t *testing.T) {
	args := sshAgentArgs{
		Action: "list",
		Socket: "/nonexistent/socket/path",
	}
	result := sshAgentList(args)
	if result.Status != "success" {
		t.Errorf("expected success status (with error in output), got %q", result.Status)
	}
	if !strings.Contains(result.Output, "Error") && !strings.Contains(result.Output, "error") {
		t.Error("expected error message about connection failure")
	}
}

func TestSSHAgentExecuteUnknownAction(t *testing.T) {
	cmd := &SSHAgentCommand{}
	task := structs.NewTask("test-1", "ssh-agent", `{"action":"badaction"}`)
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Errorf("expected error, got %q", result.Status)
	}
	if !strings.Contains(result.Output, "Unknown action") {
		t.Errorf("expected 'Unknown action' in output, got %q", result.Output)
	}
}

func TestSSHAgentExecuteDefaultAction(t *testing.T) {
	// Empty params should default to "list"
	cmd := &SSHAgentCommand{}
	// Unset SSH_AUTH_SOCK to get predictable behavior
	origSock := os.Getenv("SSH_AUTH_SOCK")
	os.Unsetenv("SSH_AUTH_SOCK")
	defer func() {
		if origSock != "" {
			os.Setenv("SSH_AUTH_SOCK", origSock)
		}
	}()

	task := structs.NewTask("test-2", "ssh-agent", "")
	result := cmd.Execute(task)
	if result.Status != "success" {
		t.Errorf("expected success, got %q", result.Status)
	}
}

func TestIsUnixSocket(t *testing.T) {
	// Regular file should not be a socket
	tmp, err := os.CreateTemp("", "test-not-socket")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmp.Name())
	tmp.Close()

	if isUnixSocket(tmp.Name()) {
		t.Error("regular file should not be detected as socket")
	}

	// Nonexistent path
	if isUnixSocket("/nonexistent/path") {
		t.Error("nonexistent path should not be detected as socket")
	}
}

func TestIsUnixSocketReal(t *testing.T) {
	// Create a real Unix socket
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "test.sock")

	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Skipf("cannot create unix socket: %v", err)
	}
	defer ln.Close()

	if !isUnixSocket(sockPath) {
		t.Error("real unix socket should be detected as socket")
	}
}

func TestFingerprintSHA256(t *testing.T) {
	// Create a mock agent.Key with known data
	key := &agent.Key{
		Format: "ssh-ed25519",
		Blob:   []byte("test-key-blob-data-for-fingerprint"),
	}
	fp := fingerprintSHA256(key)
	if !strings.HasPrefix(fp, "SHA256:") {
		t.Errorf("fingerprint should start with SHA256:, got %q", fp)
	}
	if len(fp) < 10 {
		t.Errorf("fingerprint too short: %q", fp)
	}

	// Same key should produce same fingerprint
	fp2 := fingerprintSHA256(key)
	if fp != fp2 {
		t.Error("same key should produce same fingerprint")
	}
}

func TestDiscoverAgentSocketsWithEnv(t *testing.T) {
	// Create a real Unix socket and set SSH_AUTH_SOCK to it
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "agent.test")

	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Skipf("cannot create unix socket: %v", err)
	}
	defer ln.Close()

	origSock := os.Getenv("SSH_AUTH_SOCK")
	os.Setenv("SSH_AUTH_SOCK", sockPath)
	defer func() {
		if origSock != "" {
			os.Setenv("SSH_AUTH_SOCK", origSock)
		} else {
			os.Unsetenv("SSH_AUTH_SOCK")
		}
	}()

	sockets := discoverAgentSockets()
	found := false
	for _, s := range sockets {
		if s.Path == sockPath && s.Source == "SSH_AUTH_SOCK" {
			found = true
			break
		}
	}
	if !found {
		t.Error("should discover socket from SSH_AUTH_SOCK env var")
	}
}

func TestListAgentKeysConnectionRefused(t *testing.T) {
	keys, err := listAgentKeys("/nonexistent/socket")
	if err == nil {
		t.Error("expected error for nonexistent socket")
	}
	if keys != nil {
		t.Error("expected nil keys for nonexistent socket")
	}
}
