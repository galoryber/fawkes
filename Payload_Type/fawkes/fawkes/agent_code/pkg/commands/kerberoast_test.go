package commands

import (
	"encoding/json"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestKerberoastCommand_Name(t *testing.T) {
	cmd := &KerberoastCommand{}
	if cmd.Name() != "kerberoast" {
		t.Errorf("expected name 'kerberoast', got %q", cmd.Name())
	}
}

func TestKerberoastCommand_Description(t *testing.T) {
	cmd := &KerberoastCommand{}
	if cmd.Description() == "" {
		t.Error("expected non-empty description")
	}
	if !strings.Contains(cmd.Description(), "T1558.003") {
		t.Error("expected MITRE ATT&CK ID in description")
	}
}

func TestKerberoastCommand_EmptyParams(t *testing.T) {
	cmd := &KerberoastCommand{}
	result := cmd.Execute(structs.Task{Params: ""})
	if result.Status != "error" {
		t.Errorf("expected error status for empty params, got %q", result.Status)
	}
}

func TestKerberoastCommand_InvalidJSON(t *testing.T) {
	cmd := &KerberoastCommand{}
	result := cmd.Execute(structs.Task{Params: "not json"})
	if result.Status != "error" {
		t.Errorf("expected error status for invalid JSON, got %q", result.Status)
	}
	if !strings.Contains(result.Output, "Error parsing") {
		t.Errorf("expected parsing error message, got %q", result.Output)
	}
}

func TestKerberoastCommand_MissingServer(t *testing.T) {
	cmd := &KerberoastCommand{}
	params, _ := json.Marshal(kerberoastArgs{
		Username: "user@domain.local",
		Password: "pass",
	})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error for missing server, got %q", result.Status)
	}
	if !strings.Contains(result.Output, "server") {
		t.Errorf("expected server-related error, got %q", result.Output)
	}
}

func TestKerberoastCommand_MissingUsername(t *testing.T) {
	cmd := &KerberoastCommand{}
	params, _ := json.Marshal(kerberoastArgs{
		Server:   "dc01",
		Password: "pass",
	})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error for missing username, got %q", result.Status)
	}
}

func TestKerberoastCommand_MissingPassword(t *testing.T) {
	cmd := &KerberoastCommand{}
	params, _ := json.Marshal(kerberoastArgs{
		Server:   "dc01",
		Username: "user@domain.local",
	})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error for missing password, got %q", result.Status)
	}
}

func TestKerberoastCommand_RealmAutoDetect(t *testing.T) {
	// This test verifies realm auto-detection from UPN format
	// It will fail to connect to a real KDC, but should get past param validation
	cmd := &KerberoastCommand{}
	params, _ := json.Marshal(kerberoastArgs{
		Server:   "192.0.2.1", // RFC 5737 documentation IP
		Username: "user@test.local",
		Password: "pass",
		SPN:      "MSSQLSvc/host.test.local",
	})
	result := cmd.Execute(structs.Task{Params: string(params)})
	// Should fail at KDC connection, not at realm detection
	if result.Status != "error" {
		// If it somehow succeeds connecting to a test IP, that's unexpected
		t.Log("Unexpected success — may have connected to something")
	}
	// Should NOT contain "realm required" error since UPN provides the realm
	if strings.Contains(result.Output, "realm required") {
		t.Errorf("realm should be auto-detected from UPN, but got: %q", result.Output)
	}
}

func TestKerberoastCommand_RealmRequired(t *testing.T) {
	cmd := &KerberoastCommand{}
	params, _ := json.Marshal(kerberoastArgs{
		Server:   "dc01",
		Username: "user_no_upn",
		Password: "pass",
	})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error for missing realm with non-UPN username, got %q", result.Status)
	}
	if !strings.Contains(result.Output, "realm") {
		t.Errorf("expected realm-related error, got %q", result.Output)
	}
}

func TestEtypeToName(t *testing.T) {
	tests := []struct {
		etype    int32
		expected string
	}{
		{17, "AES128-CTS"},
		{18, "AES256-CTS"},
		{23, "RC4-HMAC"},
		{99, "etype-99"},
	}
	for _, tt := range tests {
		result := etypeToName(tt.etype)
		if result != tt.expected {
			t.Errorf("etypeToName(%d) = %q, want %q", tt.etype, result, tt.expected)
		}
	}
}

func TestBuildKrb5Config(t *testing.T) {
	config := buildKrb5Config("TEST.LOCAL", "192.168.1.1")
	if !strings.Contains(config, "TEST.LOCAL") {
		t.Error("config should contain realm")
	}
	if !strings.Contains(config, "192.168.1.1:88") {
		t.Error("config should contain KDC with port 88")
	}
	if !strings.Contains(config, "dns_lookup_kdc = false") {
		t.Error("config should disable DNS lookup")
	}
}

func TestKerberoastCommand_Registration(t *testing.T) {
	Initialize()
	cmd := GetCommand("kerberoast")
	if cmd == nil {
		t.Fatal("kerberoast command not registered")
	}
	if cmd.Name() != "kerberoast" {
		t.Errorf("expected name 'kerberoast', got %q", cmd.Name())
	}
}
