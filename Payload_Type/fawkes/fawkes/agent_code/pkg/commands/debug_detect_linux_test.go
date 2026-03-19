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
	if len(checks) < 5 {
		t.Errorf("expected at least 5 checks, got %d", len(checks))
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

func TestCheckProcMaps(t *testing.T) {
	result := checkProcMaps()
	if !strings.Contains(result.Name, "Memory Maps") {
		t.Errorf("expected 'Memory Maps' in name, got %q", result.Name)
	}
	// In normal CI, should be CLEAN (no frida/valgrind)
	if result.Status == "ERROR" {
		t.Errorf("unexpected error: %s", result.Details)
	}
	if result.Status == "CLEAN" && !strings.Contains(result.Details, "mappings") {
		t.Errorf("CLEAN status should report mapping count, got %q", result.Details)
	}
}

func TestCheckProcStatus(t *testing.T) {
	result := checkProcStatus()
	if !strings.Contains(result.Name, "Process Status") {
		t.Errorf("expected 'Process Status' in name, got %q", result.Name)
	}
	// Should not error on a normal system
	if result.Status == "ERROR" {
		t.Errorf("unexpected error: %s", result.Details)
	}
}

func TestCheckSandboxIndicators(t *testing.T) {
	result := checkSandboxIndicators()
	if !strings.Contains(result.Name, "VM/Sandbox") {
		t.Errorf("expected 'VM/Sandbox' in name, got %q", result.Name)
	}
	// Status should be valid
	switch result.Status {
	case "CLEAN", "WARNING":
		// expected
	default:
		t.Errorf("unexpected status %q: %s", result.Status, result.Details)
	}
}

func TestCheckProcMaps_NoInstrumentation(t *testing.T) {
	// In a normal Go test, there should be no frida/valgrind in memory maps
	result := checkProcMaps()
	if result.Status == "DETECTED" {
		t.Logf("Instrumentation detected (may be expected in some CI): %s", result.Details)
	}
}

func TestCheckSandboxIndicators_VMDetection(t *testing.T) {
	// On CI runners (often VMs), this may detect hypervisor flag
	result := checkSandboxIndicators()
	if result.Status == "WARNING" {
		t.Logf("VM/sandbox indicators found (expected on CI): %s", result.Details)
	}
}
