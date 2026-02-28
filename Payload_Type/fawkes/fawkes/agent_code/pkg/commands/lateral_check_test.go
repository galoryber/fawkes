package commands

import (
	"encoding/json"
	"net"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestLateralCheckName(t *testing.T) {
	cmd := &LateralCheckCommand{}
	if cmd.Name() != "lateral-check" {
		t.Errorf("Expected 'lateral-check', got '%s'", cmd.Name())
	}
}

func TestLateralCheckDescription(t *testing.T) {
	cmd := &LateralCheckCommand{}
	if cmd.Description() == "" {
		t.Error("Description should not be empty")
	}
}

func TestLateralCheckBadJSON(t *testing.T) {
	cmd := &LateralCheckCommand{}
	result := cmd.Execute(structs.Task{Params: "not json"})
	if result.Status != "error" {
		t.Error("Expected error for bad JSON")
	}
}

func TestLateralCheckMissingHosts(t *testing.T) {
	cmd := &LateralCheckCommand{}
	params, _ := json.Marshal(lateralCheckArgs{})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Error("Expected error for missing hosts")
	}
	if !strings.Contains(result.Output, "-hosts parameter required") {
		t.Errorf("Expected hosts required error, got: %s", result.Output)
	}
}

func TestLateralCheckTooManyHosts(t *testing.T) {
	cmd := &LateralCheckCommand{}
	// /22 = 1024 hosts
	params, _ := json.Marshal(lateralCheckArgs{Hosts: "10.0.0.0/22"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Error("Expected error for too many hosts")
	}
	if !strings.Contains(result.Output, "too many hosts") {
		t.Errorf("Expected too many hosts error, got: %s", result.Output)
	}
}

func TestLateralCheckInvalidCIDR(t *testing.T) {
	cmd := &LateralCheckCommand{}
	params, _ := json.Marshal(lateralCheckArgs{Hosts: "not-a-cidr/33"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Error("Expected error for invalid CIDR")
	}
	if !strings.Contains(result.Output, "no valid hosts") {
		t.Errorf("Expected no valid hosts error, got: %s", result.Output)
	}
}

// Test actual connectivity with localhost (should have some ports open/closed)
func TestLateralCheckLocalhost(t *testing.T) {
	cmd := &LateralCheckCommand{}
	params, _ := json.Marshal(lateralCheckArgs{Hosts: "127.0.0.1", Timeout: 1})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Errorf("Expected success, got %s: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "LATERAL MOVEMENT CHECK") {
		t.Errorf("Expected header, got: %s", result.Output)
	}
	if !strings.Contains(result.Output, "127.0.0.1") {
		t.Errorf("Expected host in output, got: %s", result.Output)
	}
	if !strings.Contains(result.Output, "1 host(s) checked") {
		t.Errorf("Expected 1 host checked summary, got: %s", result.Output)
	}
}

func TestLateralCheckMultipleHosts(t *testing.T) {
	cmd := &LateralCheckCommand{}
	params, _ := json.Marshal(lateralCheckArgs{Hosts: "127.0.0.1,127.0.0.2", Timeout: 1})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Errorf("Expected success, got %s: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "2 host(s) checked") {
		t.Errorf("Expected 2 hosts checked, got: %s", result.Output)
	}
}

func TestLateralCheckDefaultTimeout(t *testing.T) {
	cmd := &LateralCheckCommand{}
	params, _ := json.Marshal(lateralCheckArgs{Hosts: "127.0.0.1"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Errorf("Expected success with default timeout, got %s: %s", result.Status, result.Output)
	}
}

// --- lateralParseHosts tests ---

func TestLateralParseHostsSingle(t *testing.T) {
	hosts := lateralParseHosts("192.168.1.1")
	if len(hosts) != 1 || hosts[0] != "192.168.1.1" {
		t.Errorf("Expected ['192.168.1.1'], got %v", hosts)
	}
}

func TestLateralParseHostsComma(t *testing.T) {
	hosts := lateralParseHosts("10.0.0.1, 10.0.0.2, 10.0.0.3")
	if len(hosts) != 3 {
		t.Errorf("Expected 3 hosts, got %d: %v", len(hosts), hosts)
	}
}

func TestLateralParseHostsDedup(t *testing.T) {
	hosts := lateralParseHosts("10.0.0.1, 10.0.0.1, 10.0.0.1")
	if len(hosts) != 1 {
		t.Errorf("Expected 1 unique host, got %d: %v", len(hosts), hosts)
	}
}

func TestLateralParseHostsCIDR(t *testing.T) {
	hosts := lateralParseHosts("10.0.0.0/30")
	// /30 = 4 IPs: .0, .1, .2, .3
	if len(hosts) != 4 {
		t.Errorf("Expected 4 hosts for /30, got %d: %v", len(hosts), hosts)
	}
}

func TestLateralParseHostsCIDR24(t *testing.T) {
	hosts := lateralParseHosts("10.0.0.0/24")
	if len(hosts) != 256 {
		t.Errorf("Expected 256 hosts for /24, got %d", len(hosts))
	}
}

func TestLateralParseHostsEmpty(t *testing.T) {
	hosts := lateralParseHosts("")
	if len(hosts) != 0 {
		t.Errorf("Expected 0 hosts for empty input, got %d", len(hosts))
	}
}

func TestLateralParseHostsMixed(t *testing.T) {
	hosts := lateralParseHosts("10.0.0.1, 192.168.1.0/30")
	// 1 standalone + 4 from /30
	if len(hosts) != 5 {
		t.Errorf("Expected 5 hosts, got %d: %v", len(hosts), hosts)
	}
}

func TestLateralParseHostsOverLimit(t *testing.T) {
	// /20 = 4096 IPs but capped at 257 (internal limit+1 check)
	hosts := lateralParseHosts("10.0.0.0/20")
	if len(hosts) > 257 {
		t.Errorf("Expected hosts capped near 257, got %d", len(hosts))
	}
}

// --- isTimeout tests ---

func TestIsTimeoutNilError(t *testing.T) {
	if isTimeout(nil) {
		t.Error("Expected false for nil error")
	}
}

// --- lateralIncIP tests ---

func TestLateralIncIP(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"10.0.0.0", "10.0.0.1"},
		{"10.0.0.255", "10.0.1.0"},
		{"10.0.255.255", "10.1.0.0"},
	}

	for _, tc := range tests {
		ip := net.ParseIP(tc.input).To4()
		lateralIncIP(ip)
		if ip.String() != tc.expected {
			t.Errorf("lateralIncIP(%s) = %s, want %s", tc.input, ip.String(), tc.expected)
		}
	}
}

func TestLateralCheckCancellation(t *testing.T) {
	task := structs.NewTask("cancel-lateral", "lateral-check", "")
	task.SetStop()

	cmd := &LateralCheckCommand{}
	params, _ := json.Marshal(lateralCheckArgs{Hosts: "127.0.0.1,127.0.0.2,127.0.0.3", Timeout: 1})
	task.Params = string(params)
	result := cmd.Execute(task)
	// Should still succeed but may have incomplete results
	if result.Status != "success" {
		t.Errorf("Expected success on cancel, got %s: %s", result.Status, result.Output)
	}
}
