//go:build !windows

package commands

import (
	"strings"
	"testing"
)

func TestBuildCrontabEntryRawEntry(t *testing.T) {
	args := crontabArgs{Entry: "*/5 * * * * /usr/bin/check"}
	entry, err := buildCrontabEntry(args)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if entry != "*/5 * * * * /usr/bin/check" {
		t.Errorf("expected raw entry, got %q", entry)
	}
}

func TestBuildCrontabEntryProgramOnly(t *testing.T) {
	args := crontabArgs{Program: "/opt/payload"}
	entry, err := buildCrontabEntry(args)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Default schedule is @reboot
	if entry != "@reboot /opt/payload" {
		t.Errorf("expected '@reboot /opt/payload', got %q", entry)
	}
}

func TestBuildCrontabEntryProgramWithSchedule(t *testing.T) {
	args := crontabArgs{Program: "/opt/payload", Schedule: "0 */4 * * *"}
	entry, err := buildCrontabEntry(args)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if entry != "0 */4 * * * /opt/payload" {
		t.Errorf("expected '0 */4 * * * /opt/payload', got %q", entry)
	}
}

func TestBuildCrontabEntryProgramWithArgs(t *testing.T) {
	args := crontabArgs{Program: "/opt/payload", Args: "--silent --output /tmp/out"}
	entry, err := buildCrontabEntry(args)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if entry != "@reboot /opt/payload --silent --output /tmp/out" {
		t.Errorf("unexpected entry: %q", entry)
	}
}

func TestBuildCrontabEntryNoEntryNoProgram(t *testing.T) {
	args := crontabArgs{Schedule: "* * * * *"}
	_, err := buildCrontabEntry(args)
	if err == nil {
		t.Error("expected error when neither entry nor program provided")
	}
}

func TestBuildCrontabEntryRawTakesPrecedence(t *testing.T) {
	// If both Entry and Program are set, Entry wins
	args := crontabArgs{Entry: "0 0 * * * /raw", Program: "/ignored"}
	entry, err := buildCrontabEntry(args)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if entry != "0 0 * * * /raw" {
		t.Errorf("expected raw entry to take precedence, got %q", entry)
	}
}

func TestMergeCrontabEmpty(t *testing.T) {
	result := mergeCrontab("", "@reboot /opt/payload")
	if result != "@reboot /opt/payload\n" {
		t.Errorf("unexpected merge result: %q", result)
	}
}

func TestMergeCrontabExisting(t *testing.T) {
	existing := "0 * * * * /usr/bin/check\n"
	result := mergeCrontab(existing, "@reboot /opt/payload")
	expected := "0 * * * * /usr/bin/check\n@reboot /opt/payload\n"
	if result != expected {
		t.Errorf("expected %q, got %q", expected, result)
	}
}

func TestMergeCrontabTrailingNewlines(t *testing.T) {
	existing := "0 * * * * /usr/bin/check\n\n\n"
	result := mergeCrontab(existing, "new-entry")
	// Should strip trailing newlines before appending
	if strings.Count(result, "new-entry") != 1 {
		t.Errorf("expected one new entry, got: %q", result)
	}
}

func TestFilterCrontabLinesNoMatch(t *testing.T) {
	lines := []string{"0 * * * * /usr/bin/check", "*/5 * * * * /opt/other"}
	kept, removed := filterCrontabLines(lines, "/nonexistent")
	if removed != 0 {
		t.Errorf("expected 0 removed, got %d", removed)
	}
	if len(kept) != 2 {
		t.Errorf("expected 2 kept, got %d", len(kept))
	}
}

func TestFilterCrontabLinesSingleMatch(t *testing.T) {
	lines := []string{"0 * * * * /usr/bin/check", "@reboot /opt/payload", "*/5 * * * * /opt/other"}
	kept, removed := filterCrontabLines(lines, "/opt/payload")
	if removed != 1 {
		t.Errorf("expected 1 removed, got %d", removed)
	}
	if len(kept) != 2 {
		t.Errorf("expected 2 kept, got %d", len(kept))
	}
	for _, line := range kept {
		if strings.Contains(line, "/opt/payload") {
			t.Error("payload line should have been removed")
		}
	}
}

func TestFilterCrontabLinesMultipleMatches(t *testing.T) {
	lines := []string{
		"@reboot /opt/payload --mode a",
		"0 * * * * /usr/bin/check",
		"*/5 * * * * /opt/payload --mode b",
	}
	kept, removed := filterCrontabLines(lines, "/opt/payload")
	if removed != 2 {
		t.Errorf("expected 2 removed, got %d", removed)
	}
	if len(kept) != 1 {
		t.Errorf("expected 1 kept, got %d", len(kept))
	}
}

func TestFilterCrontabLinesEmptyInput(t *testing.T) {
	kept, removed := filterCrontabLines(nil, "anything")
	if removed != 0 || kept != nil {
		t.Errorf("expected nil/0 for empty input, got %v/%d", kept, removed)
	}
}

func TestFilterCrontabLinesAllRemoved(t *testing.T) {
	lines := []string{"job1 /path", "job2 /path"}
	kept, removed := filterCrontabLines(lines, "/path")
	if removed != 2 {
		t.Errorf("expected 2 removed, got %d", removed)
	}
	if len(kept) != 0 {
		t.Errorf("expected 0 kept, got %d", len(kept))
	}
}
