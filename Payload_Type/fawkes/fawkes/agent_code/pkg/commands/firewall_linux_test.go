//go:build linux

package commands

import (
	"encoding/json"
	"os/exec"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestFirewallLinuxNameAndDescription(t *testing.T) {
	cmd := &FirewallCommand{}
	if cmd.Name() != "firewall" {
		t.Errorf("Expected name 'firewall', got '%s'", cmd.Name())
	}
	if cmd.Description() == "" {
		t.Error("Description should not be empty")
	}
}

func TestFirewallLinuxEmptyParams(t *testing.T) {
	cmd := &FirewallCommand{}
	task := structs.Task{Params: ""}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Error("Expected error for empty params")
	}
	if !strings.Contains(result.Output, "parameters required") {
		t.Errorf("Expected parameters required error, got: %s", result.Output)
	}
}

func TestFirewallLinuxInvalidJSON(t *testing.T) {
	cmd := &FirewallCommand{}
	task := structs.Task{Params: "not json"}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Error("Expected error status for invalid JSON")
	}
	if !strings.Contains(result.Output, "Error parsing parameters") {
		t.Errorf("Expected parsing error, got: %s", result.Output)
	}
}

func TestFirewallLinuxUnknownAction(t *testing.T) {
	cmd := &FirewallCommand{}
	params, _ := json.Marshal(map[string]string{"action": "nonexistent"})
	task := structs.Task{Params: string(params)}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Error("Expected error for unknown action")
	}
	if !strings.Contains(result.Output, "Unknown action") {
		t.Errorf("Expected unknown action error, got: %s", result.Output)
	}
}

func TestFirewallLinuxEnableUnsupported(t *testing.T) {
	cmd := &FirewallCommand{}
	params, _ := json.Marshal(map[string]string{"action": "enable"})
	task := structs.Task{Params: string(params)}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Error("Expected error for enable on Linux")
	}
	if !strings.Contains(result.Output, "global firewall toggle") {
		t.Errorf("Expected toggle message, got: %s", result.Output)
	}
}

func TestFirewallLinuxDisableUnsupported(t *testing.T) {
	cmd := &FirewallCommand{}
	params, _ := json.Marshal(map[string]string{"action": "disable"})
	task := structs.Task{Params: string(params)}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Error("Expected error for disable on Linux")
	}
	if !strings.Contains(result.Output, "global firewall toggle") {
		t.Errorf("Expected toggle message, got: %s", result.Output)
	}
}

func TestFirewallLinuxActionCaseInsensitive(t *testing.T) {
	cmd := &FirewallCommand{}
	// STATUS (uppercase) should be recognized
	params, _ := json.Marshal(map[string]string{"action": "STATUS"})
	task := structs.Task{Params: string(params)}
	result := cmd.Execute(task)
	// Should not get "Unknown action"
	if strings.Contains(result.Output, "Unknown action") {
		t.Error("Action should be case-insensitive")
	}
}

func TestFirewallLinuxBackendDetection(t *testing.T) {
	backend := linuxFirewallBackend()
	// On a typical Linux system, at least iptables should be available
	// But in CI/containers it might not be — just verify it returns a valid value
	if backend != "" && backend != "nft" && backend != "iptables" {
		t.Errorf("Unexpected backend: %s (expected 'nft', 'iptables', or '')", backend)
	}
}

func TestFirewallLinuxStatus(t *testing.T) {
	if linuxFirewallBackend() == "" {
		t.Skip("No firewall backend available")
	}

	cmd := &FirewallCommand{}
	params, _ := json.Marshal(map[string]string{"action": "status"})
	task := structs.Task{Params: string(params)}
	result := cmd.Execute(task)

	// Status should succeed even as non-root (may have limited info)
	if result.Status != "success" {
		t.Logf("Status returned error (likely needs root): %s", result.Output)
		return
	}
	if !strings.Contains(result.Output, "Linux Firewall Status") {
		t.Errorf("Expected header, got: %s", result.Output)
	}
	if !strings.Contains(result.Output, "Backend:") {
		t.Errorf("Expected backend info, got: %s", result.Output)
	}
}

func TestFirewallLinuxList(t *testing.T) {
	if linuxFirewallBackend() == "" {
		t.Skip("No firewall backend available")
	}

	cmd := &FirewallCommand{}
	params, _ := json.Marshal(map[string]string{"action": "list"})
	task := structs.Task{Params: string(params)}
	result := cmd.Execute(task)

	// May fail without root, that's ok
	if result.Status == "success" {
		if !strings.Contains(result.Output, "Linux Firewall Rules") {
			t.Errorf("Expected header, got: %s", result.Output)
		}
		if !strings.Contains(result.Output, "Backend:") {
			t.Errorf("Expected backend info, got: %s", result.Output)
		}
	}
}

func TestFirewallLinuxListFilter(t *testing.T) {
	if linuxFirewallBackend() == "" {
		t.Skip("No firewall backend available")
	}

	cmd := &FirewallCommand{}
	params, _ := json.Marshal(map[string]string{"action": "list", "filter": "ACCEPT"})
	task := structs.Task{Params: string(params)}
	result := cmd.Execute(task)

	// Should succeed or fail (root needed) — either is valid in test
	if result.Status == "success" {
		if !strings.Contains(result.Output, "Linux Firewall Rules") {
			t.Errorf("Expected header, got: %s", result.Output)
		}
	}
}

func TestFirewallLinuxAddPortRequiresProtocol(t *testing.T) {
	if linuxFirewallBackend() != "iptables" {
		t.Skip("Test specific to iptables backend")
	}

	cmd := &FirewallCommand{}
	params, _ := json.Marshal(firewallArgs{
		Action:     "add",
		Port:       "443",
		Protocol:   "any",
		RuleAction: "allow",
	})
	task := structs.Task{Params: string(params)}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Error("Expected error when port specified with protocol 'any'")
	}
	if !strings.Contains(result.Output, "port requires protocol") {
		t.Errorf("Expected protocol required error, got: %s", result.Output)
	}
}

func TestFirewallLinuxDeletePortRequiresProtocol(t *testing.T) {
	if linuxFirewallBackend() != "iptables" {
		t.Skip("Test specific to iptables backend")
	}

	cmd := &FirewallCommand{}
	params, _ := json.Marshal(firewallArgs{
		Action:     "delete",
		Port:       "443",
		Protocol:   "any",
		RuleAction: "allow",
	})
	task := structs.Task{Params: string(params)}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Error("Expected error when port specified with protocol 'any'")
	}
	if !strings.Contains(result.Output, "port requires protocol") {
		t.Errorf("Expected protocol required error, got: %s", result.Output)
	}
}

func TestFirewallLinuxNftDeleteRequiresName(t *testing.T) {
	if linuxFirewallBackend() != "nft" {
		t.Skip("Test specific to nftables backend")
	}

	cmd := &FirewallCommand{}
	params, _ := json.Marshal(firewallArgs{
		Action: "delete",
		Name:   "",
	})
	task := structs.Task{Params: string(params)}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Error("Expected error for nft delete without name")
	}
	if !strings.Contains(result.Output, "name") {
		t.Errorf("Expected name required error, got: %s", result.Output)
	}
}

func TestFirewallLinuxViaExecute(t *testing.T) {
	cmd := &FirewallCommand{}

	params, _ := json.Marshal(map[string]string{"action": "status"})
	task := structs.NewTask("fw-test-1", "firewall", string(params))
	result := cmd.Execute(task)
	// Even if it fails (no backend or no root), it shouldn't panic
	if result.Output == "" {
		t.Error("Expected some output")
	}
}

func TestFirewallLinuxNoBackend(t *testing.T) {
	// Save and clear PATH to simulate no backend
	origPath := lookPathFunc
	lookPathFunc = func(name string) (string, error) {
		return "", exec.ErrNotFound
	}
	defer func() { lookPathFunc = origPath }()

	result := linuxFirewallStatus()
	if result.Status != "error" {
		t.Error("Expected error when no backend found")
	}
	if !strings.Contains(result.Output, "Neither nft nor iptables") {
		t.Errorf("Expected backend not found error, got: %s", result.Output)
	}
}
