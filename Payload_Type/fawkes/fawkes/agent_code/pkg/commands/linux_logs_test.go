//go:build linux

package commands

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestLinuxLogsName(t *testing.T) {
	cmd := &LinuxLogsCommand{}
	if cmd.Name() != "linux-logs" {
		t.Errorf("expected 'linux-logs', got %q", cmd.Name())
	}
}

func TestLinuxLogsEmptyParams(t *testing.T) {
	cmd := &LinuxLogsCommand{}
	result := cmd.Execute(structs.Task{Params: ""})
	if result.Status != "error" {
		t.Errorf("expected error, got %s", result.Status)
	}
}

func TestLinuxLogsBadJSON(t *testing.T) {
	cmd := &LinuxLogsCommand{}
	result := cmd.Execute(structs.Task{Params: "not json"})
	if result.Status != "error" {
		t.Errorf("expected error, got %s", result.Status)
	}
}

func TestLinuxLogsInvalidAction(t *testing.T) {
	cmd := &LinuxLogsCommand{}
	result := cmd.Execute(structs.Task{Params: `{"action":"invalid"}`})
	if result.Status != "error" || !strings.Contains(result.Output, "Unknown action") {
		t.Errorf("expected unknown action error, got %s: %s", result.Status, result.Output)
	}
}

func TestLinuxLogsList(t *testing.T) {
	cmd := &LinuxLogsCommand{}
	result := cmd.Execute(structs.Task{Params: `{"action":"list"}`})
	if result.Status != "success" {
		t.Errorf("expected success, got %s: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "Log Files") {
		t.Errorf("expected 'Log Files' in output, got: %s", result.Output)
	}
	if !strings.Contains(result.Output, "Login Record Files") {
		t.Errorf("expected 'Login Record Files' in output, got: %s", result.Output)
	}
}

func TestLinuxLogsReadMissingFile(t *testing.T) {
	cmd := &LinuxLogsCommand{}
	result := cmd.Execute(structs.Task{Params: `{"action":"read"}`})
	if result.Status != "error" || !strings.Contains(result.Output, "file parameter required") {
		t.Errorf("expected file required error, got %s: %s", result.Status, result.Output)
	}
}

func TestLinuxLogsReadNonexistent(t *testing.T) {
	cmd := &LinuxLogsCommand{}
	result := cmd.Execute(structs.Task{Params: `{"action":"read","file":"/tmp/nonexistent_log_test_12345"}`})
	if result.Status != "error" || !strings.Contains(result.Output, "Error reading") {
		t.Errorf("expected error reading, got %s: %s", result.Status, result.Output)
	}
}

func TestLinuxLogsReadWithSearch(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "test.log")
	content := "Jan 1 10:00:00 host sshd[1234]: Accepted publickey for root\n" +
		"Jan 1 10:01:00 host cron[5678]: some cron job\n" +
		"Jan 1 10:02:00 host sshd[1235]: Failed password for admin\n"
	os.WriteFile(logFile, []byte(content), 0644)

	cmd := &LinuxLogsCommand{}
	result := cmd.Execute(structs.Task{Params: `{"action":"read","file":"` + logFile + `","search":"sshd"}`})
	if result.Status != "success" {
		t.Errorf("expected success, got %s: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "sshd") {
		t.Errorf("expected sshd lines in output: %s", result.Output)
	}
	if strings.Contains(result.Output, "cron") {
		t.Errorf("should not contain cron lines after filtering: %s", result.Output)
	}
}

func TestLinuxLogsClearMissingFile(t *testing.T) {
	cmd := &LinuxLogsCommand{}
	result := cmd.Execute(structs.Task{Params: `{"action":"clear"}`})
	if result.Status != "error" || !strings.Contains(result.Output, "file parameter required") {
		t.Errorf("expected file required error, got %s: %s", result.Status, result.Output)
	}
}

func TestLinuxLogsTruncateMissingSearch(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "test.log")
	os.WriteFile(logFile, []byte("test\n"), 0644)

	cmd := &LinuxLogsCommand{}
	result := cmd.Execute(structs.Task{Params: `{"action":"truncate","file":"` + logFile + `"}`})
	if result.Status != "error" || !strings.Contains(result.Output, "search parameter required") {
		t.Errorf("expected search required error, got %s: %s", result.Status, result.Output)
	}
}

func TestLinuxLogsTruncateLifecycle(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "test.log")
	content := "Line 1: normal activity\nLine 2: SUSPICIOUS connection from 10.0.0.1\nLine 3: normal activity\nLine 4: SUSPICIOUS login attempt\n"
	os.WriteFile(logFile, []byte(content), 0644)

	cmd := &LinuxLogsCommand{}

	// Truncate lines matching "SUSPICIOUS"
	result := cmd.Execute(structs.Task{Params: `{"action":"truncate","file":"` + logFile + `","search":"SUSPICIOUS"}`})
	if result.Status != "success" || !strings.Contains(result.Output, "Removed 2 lines") {
		t.Errorf("expected 2 lines removed, got %s: %s", result.Status, result.Output)
	}

	// Read back
	result = cmd.Execute(structs.Task{Params: `{"action":"read","file":"` + logFile + `"}`})
	if strings.Contains(result.Output, "SUSPICIOUS") {
		t.Errorf("SUSPICIOUS lines should be removed: %s", result.Output)
	}
	if !strings.Contains(result.Output, "normal activity") {
		t.Errorf("normal lines should remain: %s", result.Output)
	}
}

func TestLinuxLogsShredLifecycle(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "test.log")
	os.WriteFile(logFile, []byte("secret data that should be destroyed\n"), 0644)

	cmd := &LinuxLogsCommand{}
	result := cmd.Execute(structs.Task{Params: `{"action":"shred","file":"` + logFile + `"}`})
	if result.Status != "success" || !strings.Contains(result.Output, "Shredded") {
		t.Errorf("expected shred success, got %s: %s", result.Status, result.Output)
	}

	// File should be empty
	info, _ := os.Stat(logFile)
	if info.Size() != 0 {
		t.Errorf("file should be 0 bytes after shred, got %d", info.Size())
	}
}

func TestLinuxLogsShredMissingFile(t *testing.T) {
	cmd := &LinuxLogsCommand{}
	result := cmd.Execute(structs.Task{Params: `{"action":"shred"}`})
	if result.Status != "error" || !strings.Contains(result.Output, "file parameter required") {
		t.Errorf("expected file required error, got %s: %s", result.Status, result.Output)
	}
}

func TestUtmpTypeName(t *testing.T) {
	tests := []struct {
		input    int16
		expected string
	}{
		{1, "RUN_LVL"},
		{2, "BOOT"},
		{7, "USER"},
		{8, "DEAD"},
		{99, "TYPE_99"},
	}
	for _, tc := range tests {
		got := utmpTypeName(tc.input)
		if got != tc.expected {
			t.Errorf("utmpTypeName(%d) = %q, want %q", tc.input, got, tc.expected)
		}
	}
}
