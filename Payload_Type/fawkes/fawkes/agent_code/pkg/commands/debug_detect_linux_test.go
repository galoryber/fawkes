//go:build linux

package commands

import (
	"strings"
	"testing"
)

func TestCheckTracerPid(t *testing.T) {
	result := checkTracerPid()
	if result.Name == "" {
		t.Error("expected non-empty check name")
	}
	if !strings.Contains(result.Name, "TracerPid") {
		t.Errorf("expected TracerPid in name, got %q", result.Name)
	}
	// In CI (not being debugged), TracerPid should be 0 → CLEAN
	if result.Status != "CLEAN" {
		t.Logf("TracerPid check: %s — %s", result.Status, result.Details)
	}
}

func TestCheckLdPreload_Default(t *testing.T) {
	result := checkLdPreload()
	if result.Name != "LD_PRELOAD" {
		t.Errorf("expected name 'LD_PRELOAD', got %q", result.Name)
	}
	// In CI, LD_PRELOAD should not be set
	if result.Status != "CLEAN" {
		t.Logf("LD_PRELOAD: %s — %s", result.Status, result.Details)
	}
}

func TestCheckLdPreload_Set(t *testing.T) {
	t.Setenv("LD_PRELOAD", "/tmp/test.so")
	result := checkLdPreload()
	if result.Status != "WARNING" {
		t.Errorf("expected WARNING when LD_PRELOAD set, got %q", result.Status)
	}
	if !strings.Contains(result.Details, "/tmp/test.so") {
		t.Errorf("expected LD_PRELOAD value in details, got %q", result.Details)
	}
}

func TestRunPlatformDebugChecks(t *testing.T) {
	checks := runPlatformDebugChecks()
	if len(checks) < 2 {
		t.Errorf("expected at least 2 checks, got %d", len(checks))
	}
	// Verify each check has a name and status
	for i, c := range checks {
		if c.Name == "" {
			t.Errorf("check[%d] has empty name", i)
		}
		if c.Status == "" {
			t.Errorf("check[%d] %q has empty status", i, c.Name)
		}
	}
}
