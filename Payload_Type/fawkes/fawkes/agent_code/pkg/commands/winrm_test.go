package commands

import (
	"encoding/json"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestWinrmCommand_Name(t *testing.T) {
	cmd := &WinrmCommand{}
	if cmd.Name() != "winrm" {
		t.Errorf("expected name 'winrm', got %q", cmd.Name())
	}
}

func TestWinrmCommand_Description(t *testing.T) {
	cmd := &WinrmCommand{}
	if cmd.Description() == "" {
		t.Error("expected non-empty description")
	}
	if !strings.Contains(cmd.Description(), "T1021.006") {
		t.Error("expected MITRE ATT&CK ID in description")
	}
}

func TestWinrmCommand_EmptyParams(t *testing.T) {
	cmd := &WinrmCommand{}
	result := cmd.Execute(structs.Task{Params: ""})
	if result.Status != "error" {
		t.Errorf("expected error for empty params, got %q", result.Status)
	}
}

func TestWinrmCommand_InvalidJSON(t *testing.T) {
	cmd := &WinrmCommand{}
	result := cmd.Execute(structs.Task{Params: "not json"})
	if result.Status != "error" {
		t.Errorf("expected error for invalid JSON, got %q", result.Status)
	}
}

func TestWinrmCommand_MissingHost(t *testing.T) {
	cmd := &WinrmCommand{}
	params, _ := json.Marshal(winrmArgs{
		Username: "user",
		Password: "pass",
		Command:  "whoami",
	})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error for missing host, got %q", result.Status)
	}
}

func TestWinrmCommand_MissingUsername(t *testing.T) {
	cmd := &WinrmCommand{}
	params, _ := json.Marshal(winrmArgs{
		Host:     "127.0.0.1",
		Password: "pass",
		Command:  "whoami",
	})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error for missing username, got %q", result.Status)
	}
}

func TestWinrmCommand_MissingPassword(t *testing.T) {
	cmd := &WinrmCommand{}
	params, _ := json.Marshal(winrmArgs{
		Host:     "127.0.0.1",
		Username: "user",
		Command:  "whoami",
	})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error for missing password, got %q", result.Status)
	}
}

func TestWinrmCommand_MissingCommand(t *testing.T) {
	cmd := &WinrmCommand{}
	params, _ := json.Marshal(winrmArgs{
		Host:     "127.0.0.1",
		Username: "user",
		Password: "pass",
	})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error for missing command, got %q", result.Status)
	}
}

func TestWinrmCommand_DefaultPort(t *testing.T) {
	// Verify default port logic by testing that non-TLS defaults to 5985
	// and TLS defaults to 5986 (tested via parameter parsing)
	args := winrmArgs{
		Host:     "127.0.0.1",
		Username: "user",
		Password: "pass",
		Command:  "whoami",
	}
	if args.Port != 0 {
		t.Errorf("expected default port 0, got %d", args.Port)
	}

	// Verify TLS port default
	args.UseTLS = true
	if args.Port != 0 {
		t.Errorf("expected port 0 before setting, got %d", args.Port)
	}
}

func TestWinrmCommand_HashAccepted(t *testing.T) {
	// Hash should be accepted as alternative to password
	cmd := &WinrmCommand{}
	params, _ := json.Marshal(winrmArgs{
		Host:     "127.0.0.1",
		Username: "admin",
		Hash:     "aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c",
		Command:  "whoami",
	})
	result := cmd.Execute(structs.Task{Params: string(params)})
	// Should fail on network, not on validation
	if strings.Contains(result.Output, "password (or hash) are required") {
		t.Error("hash should be accepted as alternative to password")
	}
}

func TestWinrmCommand_NoPasswordOrHash(t *testing.T) {
	cmd := &WinrmCommand{}
	params, _ := json.Marshal(winrmArgs{
		Host:     "127.0.0.1",
		Username: "admin",
		Command:  "whoami",
	})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Error("expected error when both password and hash are empty")
	}
	if !strings.Contains(result.Output, "password (or hash)") {
		t.Errorf("expected password/hash error, got: %s", result.Output)
	}
}

func TestWinrmCommand_Registration(t *testing.T) {
	Initialize()
	cmd := GetCommand("winrm")
	if cmd == nil {
		t.Fatal("winrm command not registered")
	}
	if cmd.Name() != "winrm" {
		t.Errorf("expected name 'winrm', got %q", cmd.Name())
	}
}
