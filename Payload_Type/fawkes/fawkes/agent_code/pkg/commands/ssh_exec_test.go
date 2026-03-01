package commands

import (
	"encoding/json"
	"testing"

	"fawkes/pkg/structs"

	"golang.org/x/crypto/ssh"
)

func TestSshExecCommandName(t *testing.T) {
	cmd := &SshExecCommand{}
	if cmd.Name() != "ssh" {
		t.Errorf("expected 'ssh', got '%s'", cmd.Name())
	}
}

func TestSshExecCommandDescription(t *testing.T) {
	cmd := &SshExecCommand{}
	if cmd.Description() == "" {
		t.Error("expected non-empty description")
	}
}

func TestSshExecEmptyParams(t *testing.T) {
	cmd := &SshExecCommand{}
	result := cmd.Execute(structs.Task{Params: ""})
	if result.Status != "error" {
		t.Errorf("expected error status, got %s", result.Status)
	}
}

func TestSshExecBadJSON(t *testing.T) {
	cmd := &SshExecCommand{}
	result := cmd.Execute(structs.Task{Params: "not json"})
	if result.Status != "error" {
		t.Errorf("expected error status, got %s", result.Status)
	}
}

func TestSshExecMissingHost(t *testing.T) {
	cmd := &SshExecCommand{}
	params, _ := json.Marshal(sshExecArgs{
		Username: "root",
		Password: "pass",
		Command:  "whoami",
	})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error for missing host, got %s", result.Status)
	}
}

func TestSshExecMissingUsername(t *testing.T) {
	cmd := &SshExecCommand{}
	params, _ := json.Marshal(sshExecArgs{
		Host:     "192.168.1.1",
		Password: "pass",
		Command:  "whoami",
	})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error for missing username, got %s", result.Status)
	}
}

func TestSshExecMissingCommand(t *testing.T) {
	cmd := &SshExecCommand{}
	params, _ := json.Marshal(sshExecArgs{
		Host:     "192.168.1.1",
		Username: "root",
		Password: "pass",
	})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error for missing command, got %s", result.Status)
	}
}

func TestSshExecMissingAuth(t *testing.T) {
	cmd := &SshExecCommand{}
	params, _ := json.Marshal(sshExecArgs{
		Host:     "192.168.1.1",
		Username: "root",
		Command:  "whoami",
	})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error for missing auth, got %s", result.Status)
	}
	if result.Output == "" {
		t.Error("expected error message about auth")
	}
}

func TestSshExecDefaultPort(t *testing.T) {
	// Verify the args struct defaults are handled
	args := sshExecArgs{
		Host:     "192.168.1.1",
		Username: "root",
		Password: "pass",
		Command:  "whoami",
	}
	if args.Port != 0 {
		t.Errorf("expected default port 0 (filled at runtime), got %d", args.Port)
	}
}

func TestSshExecNonexistentHost(t *testing.T) {
	cmd := &SshExecCommand{}
	// Use 127.0.0.1 on a non-listening port so the connection is refused
	// instantly, rather than 192.168.255.254 which times out after 3s waiting
	// for a non-existent host.
	params, _ := json.Marshal(sshExecArgs{
		Host:     "127.0.0.1",
		Username: "root",
		Password: "pass",
		Command:  "whoami",
		Port:     19999,
		Timeout:  1,
	})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error for unreachable host, got %s", result.Status)
	}
}

func TestSshExecBadKeyPath(t *testing.T) {
	cmd := &SshExecCommand{}
	params, _ := json.Marshal(sshExecArgs{
		Host:     "192.168.1.1",
		Username: "root",
		KeyPath:  "/nonexistent/key",
		Command:  "whoami",
	})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error for bad key path, got %s", result.Status)
	}
}

func TestSshExecBadKeyData(t *testing.T) {
	cmd := &SshExecCommand{}
	params, _ := json.Marshal(sshExecArgs{
		Host:     "192.168.1.1",
		Username: "root",
		KeyData:  "not a valid PEM key",
		Command:  "whoami",
	})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error for bad key data, got %s", result.Status)
	}
}

func TestParsePrivateKeyInvalid(t *testing.T) {
	_, err := parsePrivateKey([]byte("not a key"), "")
	if err == nil {
		t.Error("expected error for invalid key data")
	}
}

func TestFormatSSHResultSuccess(t *testing.T) {
	args := sshExecArgs{
		Host:     "192.168.1.1",
		Username: "root",
		Password: "pass",
		Command:  "whoami",
		Port:     22,
	}
	result := formatSSHResult(args, "192.168.1.1:22", []byte("root\n"), nil)
	if result.Status != "success" {
		t.Errorf("expected success, got %s", result.Status)
	}
	if result.Output == "" {
		t.Error("expected non-empty output")
	}
}

func TestFormatSSHResultExitError(t *testing.T) {
	args := sshExecArgs{
		Host:     "192.168.1.1",
		Username: "root",
		Password: "pass",
		Command:  "false",
		Port:     22,
	}
	exitErr := &ssh.ExitError{Waitmsg: ssh.Waitmsg{}}
	result := formatSSHResult(args, "192.168.1.1:22", []byte(""), exitErr)
	// Non-zero exit with ExitError should still be "success" (command ran, just non-zero exit)
	if result.Status != "success" {
		t.Errorf("expected success for exit error, got %s", result.Status)
	}
}

func TestFormatSSHResultWithKeyPath(t *testing.T) {
	args := sshExecArgs{
		Host:     "192.168.1.1",
		Username: "root",
		KeyPath:  "/home/root/.ssh/id_rsa",
		Command:  "id",
		Port:     22,
	}
	result := formatSSHResult(args, "192.168.1.1:22", []byte("uid=0(root)\n"), nil)
	if result.Status != "success" {
		t.Errorf("expected success, got %s", result.Status)
	}
}

func TestFormatSSHResultWithKeyData(t *testing.T) {
	args := sshExecArgs{
		Host:     "192.168.1.1",
		Username: "root",
		KeyData:  "-----BEGIN OPENSSH PRIVATE KEY-----\n...\n-----END OPENSSH PRIVATE KEY-----",
		Command:  "id",
		Port:     22,
	}
	result := formatSSHResult(args, "192.168.1.1:22", []byte("uid=0(root)\n"), nil)
	if result.Status != "success" {
		t.Errorf("expected success, got %s", result.Status)
	}
}
