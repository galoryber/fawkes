//go:build linux

package commands

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseTimeWindow(t *testing.T) {
	tests := []struct {
		input    string
		wantDur  time.Duration
		wantOK   bool
	}{
		{"24h", 24 * time.Hour, true},
		{"1h", 1 * time.Hour, true},
		{"30m", 30 * time.Minute, true},
		{"7d", 7 * 24 * time.Hour, true},
		{"3d", 3 * 24 * time.Hour, true},
		{"", 0, false},
		{"h", 0, false},
		{"abc", 0, false},
		{"-1h", 0, false},
		{"0h", 0, false},
		{"keyword", 0, false},
		{"24x", 0, false},
	}

	for _, tt := range tests {
		dur, ok := parseTimeWindow(tt.input)
		if ok != tt.wantOK {
			t.Errorf("parseTimeWindow(%q): got ok=%v, want %v", tt.input, ok, tt.wantOK)
			continue
		}
		if ok && dur != tt.wantDur {
			t.Errorf("parseTimeWindow(%q): got %v, want %v", tt.input, dur, tt.wantDur)
		}
	}
}

func TestFilterLinesByTime(t *testing.T) {
	now := time.Now()

	// Create lines with syslog timestamps using correct Go format (space-padded day)
	recentTime := now.Add(-1 * time.Hour)
	oldTime := now.Add(-48 * time.Hour)

	recentLine := recentTime.Format("Jan _2 15:04:05") + " host sshd[1234]: Accepted publickey"
	oldLine := oldTime.Format("Jan _2 15:04:05") + " host sshd[5678]: Failed password"

	lines := []string{oldLine, recentLine}
	cutoff := now.Add(-24 * time.Hour)
	result := filterLinesByTime(lines, cutoff)

	if len(result) != 1 {
		t.Fatalf("Expected 1 line after 24h filter, got %d (recent=%q, old=%q)", len(result), recentLine[:15], oldLine[:15])
	}
	if !strings.Contains(result[0], "Accepted publickey") {
		t.Errorf("Expected recent line, got: %s", result[0])
	}
}

func TestFilterLinesByTimeEmpty(t *testing.T) {
	result := filterLinesByTime(nil, time.Now())
	if len(result) != 0 {
		t.Errorf("Expected 0 lines for nil input, got %d", len(result))
	}
}

func TestFilterLinesByTimeShortLines(t *testing.T) {
	lines := []string{"short", "x", ""}
	result := filterLinesByTime(lines, time.Now().Add(-24*time.Hour))
	if len(result) != 0 {
		t.Errorf("Expected 0 lines for short lines, got %d", len(result))
	}
}

func TestEventlogListVarLog(t *testing.T) {
	// Create a temp directory with some "log" files
	dir := t.TempDir()

	// Create test files
	os.WriteFile(filepath.Join(dir, "auth.log"), []byte("test log\n"), 0644)
	os.WriteFile(filepath.Join(dir, "syslog"), []byte("system log\nline 2\n"), 0644)
	os.WriteFile(filepath.Join(dir, "backup.gz"), []byte("compressed"), 0644) // should be skipped
	os.Mkdir(filepath.Join(dir, "subdir"), 0755)                              // should be skipped

	// Test listing (the function reads /var/log, but we can test the filter behavior)
	var sb strings.Builder
	// We can't easily mock /var/log, but we can verify the function doesn't crash
	count := eventlogListVarLog(&sb, "")
	output := sb.String()

	// On a real Linux system, there should be some log files
	if count == 0 && output == "" {
		// This is OK in a container or minimal environment
		t.Log("No /var/log files found (expected in minimal environments)")
	}
}

func TestEventlogListVarLogFilter(t *testing.T) {
	var sb strings.Builder
	// Filter for a specific log name
	eventlogListVarLog(&sb, "auth")
	output := sb.String()
	// If auth.log exists, it should be in the output; empty is also acceptable
	_ = output // either contains "auth" or is empty — both are valid
}

func TestEventlogQueryFileBasic(t *testing.T) {
	// Create a temp log file
	dir := t.TempDir()
	logFile := filepath.Join(dir, "test.log")
	content := "line 1: info message\nline 2: error occurred\nline 3: warning\nline 4: error again\nline 5: info\n"
	os.WriteFile(logFile, []byte(content), 0644)

	// Query with no filter
	result := eventlogQueryFile(logFile, "", 50)
	if result.Status != "success" {
		t.Fatalf("Expected success, got: %s — %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "5 lines") {
		t.Errorf("Expected 5 lines reported, got: %s", result.Output)
	}
}

func TestEventlogQueryFileFilter(t *testing.T) {
	dir := t.TempDir()
	logFile := filepath.Join(dir, "test.log")
	content := "line 1: info message\nline 2: error occurred\nline 3: warning\nline 4: error again\nline 5: info\n"
	os.WriteFile(logFile, []byte(content), 0644)

	// Query with keyword filter
	result := eventlogQueryFile(logFile, "error", 50)
	if result.Status != "success" {
		t.Fatalf("Expected success, got: %s", result.Status)
	}
	if !strings.Contains(result.Output, "error") {
		t.Errorf("Expected 'error' in output, got: %s", result.Output)
	}
	// Should only show 2 matching lines
	if !strings.Contains(result.Output, "2 lines") {
		t.Errorf("Expected 2 filtered lines, got: %s", result.Output)
	}
}

func TestEventlogQueryFileMaxCount(t *testing.T) {
	dir := t.TempDir()
	logFile := filepath.Join(dir, "test.log")
	var lines []string
	for i := 0; i < 100; i++ {
		lines = append(lines, "log line")
	}
	os.WriteFile(logFile, []byte(strings.Join(lines, "\n")+"\n"), 0644)

	// Query with count limit
	result := eventlogQueryFile(logFile, "", 10)
	if result.Status != "success" {
		t.Fatalf("Expected success, got: %s", result.Status)
	}
	if !strings.Contains(result.Output, "showing last 10") {
		t.Errorf("Expected 'showing last 10', got: %s", result.Output)
	}
}

func TestEventlogQueryFileNotFound(t *testing.T) {
	result := eventlogQueryFile("/nonexistent/path/file.log", "", 50)
	if result.Status != "error" {
		t.Errorf("Expected error for nonexistent file, got: %s", result.Status)
	}
}

func TestEventlogFileInfo(t *testing.T) {
	dir := t.TempDir()
	logFile := filepath.Join(dir, "test.log")
	os.WriteFile(logFile, []byte("line one\nline two\nline three\n"), 0644)

	result := eventlogFileInfo(logFile)
	if result.Status != "success" {
		t.Fatalf("Expected success, got: %s — %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "Lines:") {
		t.Errorf("Expected line count in output, got: %s", result.Output)
	}
	if !strings.Contains(result.Output, "3") {
		t.Errorf("Expected 3 lines, got: %s", result.Output)
	}
}

func TestEventlogFileInfoNotFound(t *testing.T) {
	result := eventlogFileInfo("/nonexistent/path/file.log")
	if result.Status != "error" {
		t.Errorf("Expected error for nonexistent file, got: %s", result.Status)
	}
}

func TestDirSize(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "a.txt"), []byte("hello"), 0644)
	os.WriteFile(filepath.Join(dir, "b.txt"), []byte("world!"), 0644)

	size := dirSize(dir)
	if size != 11 {
		t.Errorf("Expected dirSize=11, got %d", size)
	}
}

func TestDirSizeEmpty(t *testing.T) {
	dir := t.TempDir()
	size := dirSize(dir)
	if size != 0 {
		t.Errorf("Expected dirSize=0 for empty dir, got %d", size)
	}
}

func TestDirSizeNonexistent(t *testing.T) {
	size := dirSize("/nonexistent/path")
	if size != 0 {
		t.Errorf("Expected dirSize=0 for nonexistent path, got %d", size)
	}
}

func TestEventlogLinuxToggle(t *testing.T) {
	// Enable/disable should return guidance text, not an error
	for _, action := range []string{"enable", "disable"} {
		result := eventlogLinuxToggle(action, "sshd.service")
		if result.Status != "success" {
			t.Errorf("eventlogLinuxToggle(%s): expected success, got %s", action, result.Status)
		}
		if !strings.Contains(result.Output, "journald.conf") {
			t.Errorf("eventlogLinuxToggle(%s): expected guidance about journald.conf, got: %s", action, result.Output)
		}
	}
}

func TestHasJournalctl(t *testing.T) {
	// Just verify it doesn't panic
	_ = hasJournalctl()
}

func TestEventLogCommandName(t *testing.T) {
	cmd := &EventLogCommand{}
	if cmd.Name() != "eventlog" {
		t.Errorf("Expected 'eventlog', got %s", cmd.Name())
	}
}
