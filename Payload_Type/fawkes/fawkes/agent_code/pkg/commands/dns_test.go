package commands

import (
	"encoding/json"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestDnsCommand_Name(t *testing.T) {
	cmd := &DnsCommand{}
	if cmd.Name() != "dns" {
		t.Errorf("expected name 'dns', got %q", cmd.Name())
	}
}

func TestDnsCommand_Description(t *testing.T) {
	cmd := &DnsCommand{}
	if cmd.Description() == "" {
		t.Error("expected non-empty description")
	}
	if !strings.Contains(cmd.Description(), "T1018") {
		t.Error("expected MITRE ATT&CK ID in description")
	}
}

func TestDnsCommand_EmptyParams(t *testing.T) {
	cmd := &DnsCommand{}
	result := cmd.Execute(structs.Task{Params: ""})
	if result.Status != "error" {
		t.Errorf("expected error for empty params, got %q", result.Status)
	}
}

func TestDnsCommand_InvalidJSON(t *testing.T) {
	cmd := &DnsCommand{}
	result := cmd.Execute(structs.Task{Params: "not json"})
	if result.Status != "error" {
		t.Errorf("expected error for invalid JSON, got %q", result.Status)
	}
}

func TestDnsCommand_MissingTarget(t *testing.T) {
	cmd := &DnsCommand{}
	params, _ := json.Marshal(dnsArgs{
		Action: "resolve",
	})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error for missing target, got %q", result.Status)
	}
}

func TestDnsCommand_MissingAction(t *testing.T) {
	cmd := &DnsCommand{}
	params, _ := json.Marshal(dnsArgs{
		Target: "example.com",
	})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error for missing action, got %q", result.Status)
	}
}

func TestDnsCommand_InvalidAction(t *testing.T) {
	cmd := &DnsCommand{}
	params, _ := json.Marshal(dnsArgs{
		Action: "invalid",
		Target: "example.com",
	})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error for invalid action, got %q", result.Status)
	}
	if !strings.Contains(result.Output, "unknown action") {
		t.Errorf("expected unknown action error, got %q", result.Output)
	}
}

func TestDnsCommand_ResolveLocalhost(t *testing.T) {
	cmd := &DnsCommand{}
	params, _ := json.Marshal(dnsArgs{
		Action: "resolve",
		Target: "localhost",
	})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Errorf("expected success resolving localhost, got %q: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "127.0.0.1") && !strings.Contains(result.Output, "::1") {
		t.Errorf("expected loopback address in output, got %q", result.Output)
	}
}

func TestDnsCommand_ReverseLocalhost(t *testing.T) {
	cmd := &DnsCommand{}
	params, _ := json.Marshal(dnsArgs{
		Action:  "reverse",
		Target:  "127.0.0.1",
		Timeout: 3,
	})
	result := cmd.Execute(structs.Task{Params: string(params)})
	// Reverse lookup of 127.0.0.1 may succeed or fail depending on system config
	// Just verify it doesn't panic
	if result.Status != "success" && result.Status != "error" {
		t.Errorf("expected success or error, got %q", result.Status)
	}
}

func TestDnsCommand_Registration(t *testing.T) {
	Initialize()
	cmd := GetCommand("dns")
	if cmd == nil {
		t.Fatal("dns command not registered")
	}
	if cmd.Name() != "dns" {
		t.Errorf("expected name 'dns', got %q", cmd.Name())
	}
}
