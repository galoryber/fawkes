package agentfunctions

import (
	"testing"
)

func TestExtractSSHExecutionInfo_Valid(t *testing.T) {
	input := "[*] SSH root@192.168.1.10 (auth: password)"
	user, host, ok := extractSSHExecutionInfo(input)
	if !ok {
		t.Fatal("expected match")
	}
	if user != "root" {
		t.Errorf("expected root, got %q", user)
	}
	if host != "192.168.1.10" {
		t.Errorf("expected 192.168.1.10, got %q", host)
	}
}

func TestExtractSSHExecutionInfo_KeyAuth(t *testing.T) {
	input := "[*] SSH admin@dc01.corp.local (auth: key:/root/.ssh/id_rsa)"
	user, host, ok := extractSSHExecutionInfo(input)
	if !ok {
		t.Fatal("expected match")
	}
	if user != "admin" {
		t.Errorf("expected admin, got %q", user)
	}
	if host != "dc01.corp.local" {
		t.Errorf("expected dc01.corp.local, got %q", host)
	}
}

func TestExtractSSHExecutionInfo_NoMatch(t *testing.T) {
	_, _, ok := extractSSHExecutionInfo("SSH connection failed: timeout")
	if ok {
		t.Error("expected no match")
	}
}

func TestExtractSSHExecutionInfo_Empty(t *testing.T) {
	_, _, ok := extractSSHExecutionInfo("")
	if ok {
		t.Error("expected no match for empty input")
	}
}

func TestSSHAuthMethod_Password(t *testing.T) {
	if m := sshAuthMethod(""); m != "password" {
		t.Errorf("expected 'password', got %q", m)
	}
}

func TestSSHAuthMethod_Key(t *testing.T) {
	if m := sshAuthMethod("/root/.ssh/id_rsa"); m != "key:/root/.ssh/id_rsa" {
		t.Errorf("expected 'key:/root/.ssh/id_rsa', got %q", m)
	}
}
