//go:build !windows

package commands

import (
	"testing"
	"time"
)

// These tests cover edge cases not in eventlog_linux_test.go

func TestParseTimeWindow_WhitespaceTrimming(t *testing.T) {
	dur, ok := parseTimeWindow("  5h  ")
	if !ok {
		t.Fatal("expected ok=true for trimmed input")
	}
	if dur != 5*time.Hour {
		t.Errorf("got %v, want %v", dur, 5*time.Hour)
	}
}

func TestParseTimeWindow_UppercaseSuffix(t *testing.T) {
	dur, ok := parseTimeWindow("10H")
	if !ok {
		t.Fatal("expected ok=true for uppercase H")
	}
	if dur != 10*time.Hour {
		t.Errorf("got %v, want %v", dur, 10*time.Hour)
	}
}

func TestParseTimeWindow_UppercaseDay(t *testing.T) {
	dur, ok := parseTimeWindow("3D")
	if !ok {
		t.Fatal("expected ok=true for uppercase D")
	}
	if dur != 3*24*time.Hour {
		t.Errorf("got %v, want %v", dur, 3*24*time.Hour)
	}
}

func TestFilterLinesByTime_MalformedTimestamp(t *testing.T) {
	lines := []string{
		"2024-01-01T00:00 host sshd: ISO format not syslog",
		"not-a-timestamp host sshd: something happened",
	}
	result := filterLinesByTime(lines, time.Now().Add(-24*time.Hour))
	if len(result) != 0 {
		t.Errorf("got %d results, want 0 for malformed timestamps", len(result))
	}
}

func TestFilterLinesByTime_SpacePaddedDay(t *testing.T) {
	now := time.Now()
	year := now.Year()

	// Create a timestamp with a single-digit day (space-padded: "Mar  3")
	ts := time.Date(year, now.Month(), 3, 10, 0, 0, 0, time.UTC)
	if ts.After(now.UTC()) {
		ts = ts.AddDate(0, -1, 0)
	}
	line := ts.Format("Jan _2 15:04:05") + " host sshd: test event"

	cutoff := ts.Add(-time.Hour)
	result := filterLinesByTime([]string{line}, cutoff)
	if len(result) != 1 {
		t.Errorf("got %d results, want 1 for space-padded day format", len(result))
	}
}

func TestFilterLinesByTime_UTCConsistency(t *testing.T) {
	// filterLinesByTime parses timestamps in UTC (time.Parse default).
	// Verify that a timestamp at 23:59 UTC passes when cutoff is 23:00 UTC.
	year := time.Now().Year()
	month := time.Now().Month()
	day := time.Now().Day()

	ts := time.Date(year, month, day, 23, 59, 0, 0, time.UTC)
	line := ts.Format("Jan _2 15:04:05") + " host sshd: late event"
	cutoff := time.Date(year, month, day, 23, 0, 0, 0, time.UTC)

	result := filterLinesByTime([]string{line}, cutoff)
	if len(result) != 1 {
		t.Errorf("got %d results, want 1 for UTC timestamp after UTC cutoff", len(result))
	}
}
