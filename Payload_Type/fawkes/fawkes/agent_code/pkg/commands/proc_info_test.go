//go:build linux

package commands

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestProcInfoCommand_Name(t *testing.T) {
	cmd := &ProcInfoCommand{}
	if cmd.Name() != "proc-info" {
		t.Errorf("Expected 'proc-info', got '%s'", cmd.Name())
	}
}

func TestProcInfoCommand_Description(t *testing.T) {
	cmd := &ProcInfoCommand{}
	if cmd.Description() == "" {
		t.Error("Description should not be empty")
	}
}

func TestProcInfo_InvalidJSON(t *testing.T) {
	cmd := &ProcInfoCommand{}
	task := structs.NewTask("test-1", "proc-info", "not-json")
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Error("Expected error for invalid JSON")
	}
}

func TestProcInfo_UnknownAction(t *testing.T) {
	cmd := &ProcInfoCommand{}
	task := structs.NewTask("test-1", "proc-info", `{"action":"invalid"}`)
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Error("Expected error for unknown action")
	}
	if !strings.Contains(result.Output, "Unknown action") {
		t.Errorf("Expected 'Unknown action' in output, got: %s", result.Output)
	}
}

func TestProcInfo_DefaultsToInfoSelf(t *testing.T) {
	cmd := &ProcInfoCommand{}
	task := structs.NewTask("test-1", "proc-info", "")
	result := cmd.Execute(task)
	if result.Status != "success" {
		t.Errorf("Expected success, got: %s - %s", result.Status, result.Output)
	}
	// Should contain current PID info
	expectedPID := fmt.Sprintf("PID %d", os.Getpid())
	if !strings.Contains(result.Output, expectedPID) {
		t.Errorf("Expected current PID in output, got: %s", result.Output)
	}
}

func TestProcInfo_InfoAction(t *testing.T) {
	cmd := &ProcInfoCommand{}
	pid := os.Getpid()
	task := structs.NewTask("test-1", "proc-info", fmt.Sprintf(`{"action":"info","pid":%d}`, pid))
	result := cmd.Execute(task)
	if result.Status != "success" {
		t.Errorf("Expected success, got: %s - %s", result.Status, result.Output)
	}

	// Verify expected sections
	checks := []string{"Process Info:", "Status:", "Executable:", "Environment", "Cgroups:", "Namespaces:"}
	for _, check := range checks {
		if !strings.Contains(result.Output, check) {
			t.Errorf("Expected '%s' in process info output", check)
		}
	}
}

func TestProcInfo_InfoNonexistentPID(t *testing.T) {
	cmd := &ProcInfoCommand{}
	task := structs.NewTask("test-1", "proc-info", `{"action":"info","pid":999999999}`)
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Error("Expected error for nonexistent PID")
	}
	if !strings.Contains(result.Output, "not found") {
		t.Errorf("Expected 'not found' in output, got: %s", result.Output)
	}
}

func TestProcInfo_InfoPID1(t *testing.T) {
	cmd := &ProcInfoCommand{}
	task := structs.NewTask("test-1", "proc-info", `{"action":"info","pid":1}`)
	result := cmd.Execute(task)
	if result.Status != "success" {
		t.Errorf("Expected success, got: %s - %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "PID 1") {
		t.Error("Expected PID 1 in output")
	}
}

func TestProcInfo_ConnectionsAction(t *testing.T) {
	cmd := &ProcInfoCommand{}
	task := structs.NewTask("test-1", "proc-info", `{"action":"connections"}`)
	result := cmd.Execute(task)
	if result.Status != "success" {
		t.Errorf("Expected success, got: %s - %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "Network Connections") {
		t.Error("Expected 'Network Connections' header in output")
	}
}

func TestProcInfo_MountsAction(t *testing.T) {
	cmd := &ProcInfoCommand{}
	task := structs.NewTask("test-1", "proc-info", `{"action":"mounts"}`)
	result := cmd.Execute(task)
	if result.Status != "success" {
		t.Errorf("Expected success, got: %s - %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "Mount Information") {
		t.Error("Expected 'Mount Information' header in output")
	}
}

func TestProcInfo_ModulesAction(t *testing.T) {
	cmd := &ProcInfoCommand{}
	task := structs.NewTask("test-1", "proc-info", `{"action":"modules"}`)
	result := cmd.Execute(task)
	if result.Status != "success" {
		t.Errorf("Expected success, got: %s - %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "Kernel Modules") {
		t.Error("Expected 'Kernel Modules' header in output")
	}
}

func TestParseHexAddr_IPv4(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"0100007F:0050", "127.0.0.1:80"},
		{"00000000:0000", "0.0.0.0:0"},
	}
	for _, tt := range tests {
		result := parseHexAddr(tt.input, false)
		if result != tt.expected {
			t.Errorf("parseHexAddr(%s, false) = %s, expected %s", tt.input, result, tt.expected)
		}
	}
}

func TestParseHexAddr_MalformedInput(t *testing.T) {
	// No colon separator
	result := parseHexAddr("nocolon", false)
	if result != "nocolon" {
		t.Errorf("Expected passthrough for malformed input, got: %s", result)
	}

	// Short hex
	result = parseHexAddr("ABCD:0050", false)
	if !strings.Contains(result, ":80") {
		t.Errorf("Expected port 80 in output, got: %s", result)
	}
}

func TestParseTCPState(t *testing.T) {
	tests := []struct {
		hex      string
		expected string
	}{
		{"01", "ESTABLISHED"},
		{"0A", "LISTEN"},
		{"06", "TIME_WAIT"},
		{"FF", "FF"}, // Unknown
	}
	for _, tt := range tests {
		result := parseTCPState(tt.hex)
		if result != tt.expected {
			t.Errorf("parseTCPState(%s) = %s, expected %s", tt.hex, result, tt.expected)
		}
	}
}

func TestParseIPv6Hex(t *testing.T) {
	// All zeros
	result := parseIPv6Hex("00000000000000000000000000000000")
	if !strings.Contains(result, "0000") {
		t.Errorf("Expected zeros in IPv6 result, got: %s", result)
	}

	// Short input — should pass through
	result = parseIPv6Hex("short")
	if result != "short" {
		t.Errorf("Expected passthrough for short input, got: %s", result)
	}
}
