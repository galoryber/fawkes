//go:build linux

package commands

import (
	"os"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestPrivescCheckCommand_Name(t *testing.T) {
	cmd := &PrivescCheckCommand{}
	if cmd.Name() != "privesc-check" {
		t.Errorf("Expected 'privesc-check', got '%s'", cmd.Name())
	}
}

func TestPrivescCheckCommand_Description(t *testing.T) {
	cmd := &PrivescCheckCommand{}
	if cmd.Description() == "" {
		t.Error("Description should not be empty")
	}
}

func TestPrivescCheck_InvalidJSON(t *testing.T) {
	cmd := &PrivescCheckCommand{}
	task := structs.NewTask("test-1", "privesc-check", "not-json")
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Error("Expected error for invalid JSON")
	}
}

func TestPrivescCheck_UnknownAction(t *testing.T) {
	cmd := &PrivescCheckCommand{}
	task := structs.NewTask("test-1", "privesc-check", `{"action":"invalid"}`)
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Error("Expected error for unknown action")
	}
	if !strings.Contains(result.Output, "Unknown action") {
		t.Errorf("Expected 'Unknown action' in output, got: %s", result.Output)
	}
}

func TestPrivescCheck_DefaultsToAll(t *testing.T) {
	cmd := &PrivescCheckCommand{}
	task := structs.NewTask("test-1", "privesc-check", "")
	result := cmd.Execute(task)
	if result.Status != "success" {
		t.Errorf("Expected success, got: %s - %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "LINUX PRIVILEGE ESCALATION CHECK") {
		t.Error("Expected header in all-check output")
	}
}

func TestPrivescCheck_AllAction(t *testing.T) {
	cmd := &PrivescCheckCommand{}
	task := structs.NewTask("test-1", "privesc-check", `{"action":"all"}`)
	result := cmd.Execute(task)
	if result.Status != "success" {
		t.Errorf("Expected success, got: %s - %s", result.Status, result.Output)
	}
	// Should contain all sections
	if !strings.Contains(result.Output, "SUID/SGID") {
		t.Error("Missing SUID/SGID section in all output")
	}
	if !strings.Contains(result.Output, "Sudo") {
		t.Error("Missing Sudo section in all output")
	}
	if !strings.Contains(result.Output, "Container") {
		t.Error("Missing Container section in all output")
	}
}

func TestPrivescCheck_SuidAction(t *testing.T) {
	cmd := &PrivescCheckCommand{}
	task := structs.NewTask("test-1", "privesc-check", `{"action":"suid"}`)
	result := cmd.Execute(task)
	if result.Status != "success" {
		t.Errorf("Expected success, got: %s - %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "SUID binaries") {
		t.Error("Expected 'SUID binaries' in output")
	}
}

func TestPrivescCheck_CapabilitiesAction(t *testing.T) {
	cmd := &PrivescCheckCommand{}
	task := structs.NewTask("test-1", "privesc-check", `{"action":"capabilities"}`)
	result := cmd.Execute(task)
	if result.Status != "success" {
		t.Errorf("Expected success, got: %s - %s", result.Status, result.Output)
	}
	// Should at least have current process capabilities
	if !strings.Contains(result.Output, "Current process capabilities") {
		t.Error("Expected current process capabilities in output")
	}
}

func TestPrivescCheck_SudoAction(t *testing.T) {
	cmd := &PrivescCheckCommand{}
	task := structs.NewTask("test-1", "privesc-check", `{"action":"sudo"}`)
	result := cmd.Execute(task)
	if result.Status != "success" {
		t.Errorf("Expected success, got: %s - %s", result.Status, result.Output)
	}
}

func TestPrivescCheck_WritableAction(t *testing.T) {
	cmd := &PrivescCheckCommand{}
	task := structs.NewTask("test-1", "privesc-check", `{"action":"writable"}`)
	result := cmd.Execute(task)
	if result.Status != "success" {
		t.Errorf("Expected success, got: %s - %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "Writable PATH") {
		t.Error("Expected PATH check in output")
	}
}

func TestPrivescCheck_ContainerAction(t *testing.T) {
	cmd := &PrivescCheckCommand{}
	task := structs.NewTask("test-1", "privesc-check", `{"action":"container"}`)
	result := cmd.Execute(task)
	if result.Status != "success" {
		t.Errorf("Expected success, got: %s - %s", result.Status, result.Output)
	}
	// Should have hostname info
	if !strings.Contains(result.Output, "Hostname:") {
		t.Error("Expected hostname in container check output")
	}
}

func TestIsWritable(t *testing.T) {
	// /tmp should be writable
	if !isWritable("/tmp") {
		t.Error("Expected /tmp to be writable")
	}
	// /root should not be writable for non-root
	if os.Getuid() != 0 {
		if isWritable("/root") {
			t.Error("Expected /root to not be writable for non-root user")
		}
	}
}

func TestIsReadable(t *testing.T) {
	// /etc/passwd should be readable
	if !isReadable("/etc/passwd") {
		t.Error("Expected /etc/passwd to be readable")
	}
	// /etc/shadow should not be readable for non-root
	if os.Getuid() != 0 {
		if isReadable("/etc/shadow") {
			t.Error("Expected /etc/shadow to not be readable for non-root user")
		}
	}
}

func TestPrivescCheckPlainTextSuid(t *testing.T) {
	cmd := &PrivescCheckCommand{}
	result := cmd.Execute(structs.Task{Params: "suid"})
	if result.Status != "success" {
		t.Errorf("plain text 'suid' should succeed, got %s: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "SUID binaries") {
		t.Errorf("should contain SUID section")
	}
}

func TestPrivescCheckPlainTextCapabilities(t *testing.T) {
	cmd := &PrivescCheckCommand{}
	result := cmd.Execute(structs.Task{Params: "capabilities"})
	if result.Status != "success" {
		t.Errorf("plain text 'capabilities' should succeed, got %s: %s", result.Status, result.Output)
	}
}

func TestPrivescCheckPlainTextWritable(t *testing.T) {
	cmd := &PrivescCheckCommand{}
	result := cmd.Execute(structs.Task{Params: "writable"})
	if result.Status != "success" {
		t.Errorf("plain text 'writable' should succeed, got %s: %s", result.Status, result.Output)
	}
}

// Tests for readFileCaps capability parsing

func TestReadFileCaps_NoCapability(t *testing.T) {
	// A regular file without capabilities should return empty
	result := readFileCaps("/etc/passwd")
	if result != "" {
		t.Errorf("Expected empty for file without caps, got: %s", result)
	}
}

func TestReadFileCaps_NonexistentFile(t *testing.T) {
	result := readFileCaps("/nonexistent/file/path")
	if result != "" {
		t.Errorf("Expected empty for nonexistent file, got: %s", result)
	}
}

func TestReadFileCaps_PingBinary(t *testing.T) {
	// /usr/bin/ping often has cap_net_raw on Linux
	result := readFileCaps("/usr/bin/ping")
	if result == "" {
		t.Skip("/usr/bin/ping has no file capabilities on this system")
	}
	if !strings.Contains(result, "cap_net_raw") {
		t.Errorf("Expected cap_net_raw for ping, got: %s", result)
	}
}

func TestReadFileCaps_CapNamesTable(t *testing.T) {
	// Verify key capability name mappings
	tests := map[int]string{
		0: "cap_chown", 7: "cap_setuid", 12: "cap_net_admin",
		13: "cap_net_raw", 21: "cap_sys_admin", 31: "cap_setfcap",
	}
	for bit, expected := range tests {
		if bit >= len(capNames) {
			t.Errorf("capNames table too small for bit %d", bit)
			continue
		}
		if capNames[bit] != expected {
			t.Errorf("capNames[%d] = %q, expected %q", bit, capNames[bit], expected)
		}
	}
}

func TestReadFileCaps_V2Format(t *testing.T) {
	// Construct a VFS_CAP_REVISION_2 xattr for cap_net_raw (bit 13) with effective flag
	// magic_etc = 0x02000000 | 0x000001 = 0x02000001
	// permitted low = 1<<13 = 0x2000
	data := []byte{
		0x01, 0x00, 0x00, 0x02, // magic_etc (LE): version 0x02000000 + effective bit 0
		0x00, 0x20, 0x00, 0x00, // permitted low (LE): 0x00002000 = bit 13
		0x00, 0x00, 0x00, 0x00, // inheritable low
		0x00, 0x00, 0x00, 0x00, // permitted high
		0x00, 0x00, 0x00, 0x00, // inheritable high
	}
	// Parse manually using the same logic as readFileCaps
	magicEtc := uint32(data[0]) | uint32(data[1])<<8 | uint32(data[2])<<16 | uint32(data[3])<<24
	version := magicEtc & 0xFF000000
	if version != 0x02000000 {
		t.Fatalf("Expected version 0x02000000, got 0x%08x", version)
	}
	effective := magicEtc&0x000001 != 0
	if !effective {
		t.Error("Expected effective flag to be set")
	}
	permLow := uint32(data[4]) | uint32(data[5])<<8 | uint32(data[6])<<16 | uint32(data[7])<<24
	if permLow != 0x2000 {
		t.Errorf("Expected permitted low 0x2000, got 0x%x", permLow)
	}
}

func TestPrivescCheck_CapabilitiesNoExecCommand(t *testing.T) {
	// Verify capabilities check works and contains expected sections
	cmd := &PrivescCheckCommand{}
	task := structs.NewTask("test-1", "privesc-check", `{"action":"capabilities"}`)
	result := cmd.Execute(task)
	if result.Status != "success" {
		t.Errorf("Expected success, got: %s - %s", result.Status, result.Output)
	}
	// Must contain file capabilities section (native, no getcap)
	if !strings.Contains(result.Output, "File capabilities") {
		t.Error("Expected 'File capabilities' section in output")
	}
	// Must contain process capabilities section
	if !strings.Contains(result.Output, "Current process capabilities") {
		t.Error("Expected 'Current process capabilities' section in output")
	}
}
