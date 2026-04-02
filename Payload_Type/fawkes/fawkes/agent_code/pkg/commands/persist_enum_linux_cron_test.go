//go:build linux

package commands

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPersistEnumCron_EmptySystem(t *testing.T) {
	// On CI, the function should not crash and should return valid output
	var sb strings.Builder
	count := persistEnumCron(&sb)
	output := sb.String()

	if !strings.Contains(output, "--- Cron Jobs ---") {
		t.Error("missing section header")
	}
	// Count should be >= 0 (may find system crons on the test machine)
	if count < 0 {
		t.Errorf("count should be >= 0, got %d", count)
	}
}

func TestPersistEnumCron_CrontabLineParsing(t *testing.T) {
	// Test the crontab line filtering logic: skip empty and comment lines
	lines := []string{
		"# This is a comment",
		"",
		"  ",
		"SHELL=/bin/bash",
		"*/5 * * * * root /usr/bin/backup.sh",
		"# another comment",
		"0 3 * * * root /usr/sbin/logrotate /etc/logrotate.conf",
	}
	var filtered []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		filtered = append(filtered, line)
	}
	if len(filtered) != 3 {
		t.Errorf("expected 3 non-comment non-empty lines, got %d: %v", len(filtered), filtered)
	}
	if filtered[0] != "SHELL=/bin/bash" {
		t.Errorf("first filtered line should be SHELL=, got %q", filtered[0])
	}
}

func TestPersistEnumCron_CronDirFiltering(t *testing.T) {
	// Test that cron.d filtering skips directories and dot files
	dir := t.TempDir()

	// Create test files
	os.WriteFile(filepath.Join(dir, "backup"), []byte("*/5 * * * * root /usr/bin/backup\n"), 0644)
	os.WriteFile(filepath.Join(dir, ".placeholder"), []byte("hidden\n"), 0644)
	os.Mkdir(filepath.Join(dir, "subdir"), 0755)
	os.WriteFile(filepath.Join(dir, "logrotate"), []byte("# comment only\n\n"), 0644)

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}

	var validEntries []string
	for _, entry := range entries {
		if entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
			continue
		}
		validEntries = append(validEntries, entry.Name())
	}
	if len(validEntries) != 2 {
		t.Errorf("expected 2 valid entries (backup, logrotate), got %d: %v", len(validEntries), validEntries)
	}
}

func TestPersistEnumAnacron_JobLineParsing(t *testing.T) {
	// Anacron format: period delay job-identifier command
	// Should skip comments, empty lines, and variable assignments
	lines := []string{
		"# /etc/anacrontab: configuration file for anacron",
		"",
		"SHELL=/bin/sh",
		"PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin",
		"HOME=/root",
		"LOGNAME=root",
		"1\t5\tcron.daily\trun-parts /etc/cron.daily",
		"7\t10\tcron.weekly\trun-parts /etc/cron.weekly",
		"@monthly\t15\tcron.monthly\trun-parts /etc/cron.monthly",
	}

	var jobs []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Skip variable assignments (contains = but no space)
		if strings.Contains(line, "=") && !strings.Contains(line, " ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 4 {
			jobs = append(jobs, strings.Join(fields[3:], " "))
		}
	}

	if len(jobs) != 3 {
		t.Errorf("expected 3 anacron jobs, got %d: %v", len(jobs), jobs)
	}
	if jobs[0] != "run-parts /etc/cron.daily" {
		t.Errorf("first job command = %q, want %q", jobs[0], "run-parts /etc/cron.daily")
	}
}

func TestPersistEnumAnacron_VariableAssignmentSkip(t *testing.T) {
	// Variable assignments have = but no spaces
	tests := []struct {
		line       string
		isVariable bool
	}{
		{"SHELL=/bin/sh", true},
		{"PATH=/usr/bin", true},
		{"HOME=/root", true},
		{"1 5 cron.daily run-parts /etc/cron.daily", false},
		{"LOGNAME=root", true},
		{"7 10 cron.weekly run-parts /etc/cron.weekly", false},
	}
	for _, tc := range tests {
		isVar := strings.Contains(tc.line, "=") && !strings.Contains(tc.line, " ")
		if isVar != tc.isVariable {
			t.Errorf("line %q: got isVariable=%v, want %v", tc.line, isVar, tc.isVariable)
		}
	}
}

func TestPersistEnumDBus_ExecLineExtraction(t *testing.T) {
	// D-Bus service files have Exec= lines
	content := `[D-BUS Service]
Name=org.freedesktop.Notifications
Exec=/usr/lib/notification-daemon/notification-daemon
`
	execLine := ""
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Exec=") {
			execLine = line[5:]
			break
		}
	}
	if execLine != "/usr/lib/notification-daemon/notification-daemon" {
		t.Errorf("execLine = %q, want /usr/lib/notification-daemon/notification-daemon", execLine)
	}
}

func TestPersistEnumDBus_NoExecLine(t *testing.T) {
	content := `[D-BUS Service]
Name=org.freedesktop.systemd1
SystemdService=dbus-org.freedesktop.systemd1.service
`
	execLine := ""
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Exec=") {
			execLine = line[5:]
			break
		}
	}
	if execLine != "" {
		t.Errorf("expected no exec line, got %q", execLine)
	}
}

