//go:build linux

package commands

import (
	"strings"
	"testing"
)

func TestUptimePlatform(t *testing.T) {
	result := uptimePlatform()
	if result == "" {
		t.Error("expected non-empty uptime output")
	}
	if !strings.Contains(result, "System Uptime") {
		t.Errorf("expected 'System Uptime' header, got: %s", result)
	}
	if !strings.Contains(result, "Uptime:") {
		t.Errorf("expected 'Uptime:' field, got: %s", result)
	}
	if !strings.Contains(result, "Boot time:") {
		t.Errorf("expected 'Boot time:' field, got: %s", result)
	}
	if !strings.Contains(result, "Load avg:") {
		t.Errorf("expected 'Load avg:' field, got: %s", result)
	}
}
