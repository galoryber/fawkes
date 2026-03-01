package commands

import (
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestUptimeCommandName(t *testing.T) {
	cmd := &UptimeCommand{}
	if cmd.Name() != "uptime" {
		t.Errorf("expected 'uptime', got '%s'", cmd.Name())
	}
}

func TestUptimeReturnsOutput(t *testing.T) {
	cmd := &UptimeCommand{}
	result := cmd.Execute(structs.Task{})
	if result.Status != "success" {
		t.Errorf("expected success, got %s: %s", result.Status, result.Output)
	}
	if result.Output == "" {
		t.Error("expected non-empty output")
	}
	if !strings.Contains(result.Output, "Uptime") {
		t.Errorf("expected 'Uptime' in output, got: %s", result.Output)
	}
}

func TestUptimeContainsBootTime(t *testing.T) {
	cmd := &UptimeCommand{}
	result := cmd.Execute(structs.Task{})
	if !strings.Contains(result.Output, "Boot time") {
		t.Errorf("expected 'Boot time' in output, got: %s", result.Output)
	}
}

func TestFormatUptime(t *testing.T) {
	tests := []struct {
		seconds  int64
		expected string
	}{
		{0, "0 second(s)"},
		{59, "59 second(s)"},
		{60, "1 minute(s)"},
		{3600, "1 hour(s)"},
		{86400, "1 day(s)"},
		{90061, "1 day(s), 1 hour(s), 1 minute(s), 1 second(s)"},
		{172800, "2 day(s)"},
	}

	for _, tc := range tests {
		result := formatUptime(tc.seconds)
		if result != tc.expected {
			t.Errorf("formatUptime(%d) = '%s', expected '%s'", tc.seconds, result, tc.expected)
		}
	}
}
