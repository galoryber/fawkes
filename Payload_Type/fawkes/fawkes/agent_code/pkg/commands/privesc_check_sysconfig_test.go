//go:build linux

package commands

import (
	"strings"
	"testing"
)

func TestPrivescCheckModprobe_ReturnsResult(t *testing.T) {
	result := privescCheckModprobe()
	if result.Status != "success" {
		t.Errorf("expected success, got %q: %s", result.Status, result.Output)
	}
	if !result.Completed {
		t.Error("expected Completed=true")
	}
	// Output should contain section headers
	if !strings.Contains(result.Output, "modprobe") {
		t.Error("expected 'modprobe' in output")
	}
}

func TestPrivescCheckLdPreload_ReturnsResult(t *testing.T) {
	result := privescCheckLdPreload()
	if result.Status != "success" {
		t.Errorf("expected success, got %q: %s", result.Status, result.Output)
	}
	if !result.Completed {
		t.Error("expected Completed=true")
	}
	// Should contain ld.so.preload reference
	if !strings.Contains(result.Output, "ld.so.preload") && !strings.Contains(result.Output, "LD_PRELOAD") {
		t.Error("expected ld.so.preload or LD_PRELOAD reference in output")
	}
}

func TestPrivescCheckSecurityModules_ReturnsResult(t *testing.T) {
	result := privescCheckSecurityModules()
	if result.Status != "success" {
		t.Errorf("expected success, got %q: %s", result.Status, result.Output)
	}
	if !result.Completed {
		t.Error("expected Completed=true")
	}
	// Should reference security modules
	if !strings.Contains(result.Output, "AppArmor") && !strings.Contains(result.Output, "SELinux") &&
		!strings.Contains(result.Output, "security") {
		t.Error("expected security module reference in output")
	}
}

func TestPrivescCheckModprobe_InstallDirectiveDetection(t *testing.T) {
	// The function should parse modprobe.d configs and detect install/remove directives
	result := privescCheckModprobe()

	// Should always produce structured output with section headers
	if !strings.Contains(result.Output, "install") && !strings.Contains(result.Output, "hooks") &&
		!strings.Contains(result.Output, "modprobe") {
		t.Error("expected modprobe-related content in output")
	}
}

func TestPrivescCheckLdPreload_ChecksEnvironment(t *testing.T) {
	result := privescCheckLdPreload()

	// Output should indicate whether LD_PRELOAD is set
	// On CI, LD_PRELOAD should typically not be set
	if !strings.Contains(result.Output, "LD_PRELOAD") && !strings.Contains(result.Output, "preload") {
		t.Error("expected LD_PRELOAD check in output")
	}
}

func TestPrivescCheckSecurityModules_DetectsAvailableModules(t *testing.T) {
	result := privescCheckSecurityModules()

	// On modern Linux, at least one LSM should be detected
	hasModule := strings.Contains(result.Output, "AppArmor") ||
		strings.Contains(result.Output, "SELinux") ||
		strings.Contains(result.Output, "not detected") ||
		strings.Contains(result.Output, "No LSM")

	if !hasModule {
		t.Error("expected either LSM detection or 'not detected' message")
	}
}
