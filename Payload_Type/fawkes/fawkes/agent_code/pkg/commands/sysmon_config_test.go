//go:build windows

package commands

import (
	"strings"
	"testing"
)

func TestSysmonCheckResult_NotInstalled(t *testing.T) {
	info := sysmonInfo{Installed: false}
	result := sysmonCheckResult(info)
	if result.Status != "success" {
		t.Errorf("status = %q, want success", result.Status)
	}
	if !strings.Contains(result.Output, "NOT DETECTED") {
		t.Error("expected NOT DETECTED in output")
	}
}

func TestSysmonCheckResult_NotInstalledWithEventChannels(t *testing.T) {
	info := sysmonInfo{
		Installed: false,
		Events:    map[string]string{"Microsoft-Windows-Sysmon/Operational": "enabled"},
	}
	result := sysmonCheckResult(info)
	if !strings.Contains(result.Output, "previous installation") {
		t.Error("expected 'previous installation' note")
	}
	if !strings.Contains(result.Output, "Sysmon/Operational") {
		t.Error("expected event channel in output")
	}
}

func TestSysmonCheckResult_Installed(t *testing.T) {
	info := sysmonInfo{
		Installed:    true,
		ServiceName:  "Sysmon64",
		DriverName:   "SysmonDrv",
		DriverLoaded: true,
		ImagePath:    `C:\Windows\Sysmon64.exe`,
		Version:      "15.0",
		HashAlgo:     "SHA256",
		Options:      0x03, // network + image loading
		RuleBytes:    4096,
		Events:       map[string]string{"Operational": "enabled"},
	}
	result := sysmonCheckResult(info)
	if result.Status != "success" {
		t.Errorf("status = %q", result.Status)
	}
	// Check all fields present in output
	checks := []string{
		"Service:  Sysmon64",
		"Driver:   SysmonDrv (loaded: true)",
		`C:\Windows\Sysmon64.exe`,
		"Version:  15.0",
		"Hash Algorithm: SHA256",
		"Options: 0x3",
		"Network connection logging",
		"Image loading logging",
		"4096 bytes of configuration loaded",
		"Operational: enabled",
	}
	for _, c := range checks {
		if !strings.Contains(result.Output, c) {
			t.Errorf("missing %q in output:\n%s", c, result.Output)
		}
	}
}

func TestSysmonCheckResult_InstalledMinimal(t *testing.T) {
	info := sysmonInfo{
		Installed:   true,
		ServiceName: "Sysmon",
		DriverName:  "SysmonDrv",
	}
	result := sysmonCheckResult(info)
	if !strings.Contains(result.Output, "Sysmon Configuration") {
		t.Error("expected configuration header")
	}
	if !strings.Contains(result.Output, "(default/not set)") {
		t.Error("expected default hash algo note")
	}
	if !strings.Contains(result.Output, "No custom rules") {
		t.Error("expected no custom rules note")
	}
}

func TestSysmonEventsResult_NotInstalled(t *testing.T) {
	info := sysmonInfo{Installed: false}
	result := sysmonEventsResult(info)
	if result.Status != "success" {
		t.Errorf("status = %q", result.Status)
	}
	if !strings.Contains(result.Output, "not detected") {
		t.Error("expected 'not detected' note")
	}
	// All events should show N/A
	if !strings.Contains(result.Output, "[N/A]") {
		t.Error("expected N/A status for events when not installed")
	}
	// Should still list all 29 event types
	if !strings.Contains(result.Output, "Event  1: Process Create") {
		t.Error("expected event 1")
	}
	if !strings.Contains(result.Output, "Event 29: FileExecutableDetected") {
		t.Error("expected event 29")
	}
}

func TestSysmonEventsResult_InstalledWithAllOptions(t *testing.T) {
	info := sysmonInfo{
		Installed:   true,
		ServiceName: "Sysmon64",
		Options:     0x0F, // all flags on
	}
	result := sysmonEventsResult(info)
	if !strings.Contains(result.Output, "Sysmon detected: Sysmon64") {
		t.Error("expected detected header")
	}
	// All events should be Active
	if strings.Contains(result.Output, "OFF") {
		t.Error("all events should be active with all flags on")
	}
	if !strings.Contains(result.Output, "[Active]") {
		t.Error("expected Active status")
	}
}

func TestSysmonEventsResult_InstalledPartialOptions(t *testing.T) {
	info := sysmonInfo{
		Installed:   true,
		ServiceName: "MySysmon",
		Options:     0x01, // only network logging
	}
	result := sysmonEventsResult(info)
	// Event 3 (network) should be Active
	if !strings.Contains(result.Output, "Network connection") {
		t.Error("expected network connection event")
	}
	// Event 7 (image loaded, flag 0x02) should be OFF
	if !strings.Contains(result.Output, "Image loaded") {
		t.Error("expected image loaded event")
	}
	// Check that some events are OFF
	if !strings.Contains(result.Output, "OFF (requires Options flag)") {
		t.Error("expected some events OFF with partial options")
	}
}

func TestSysmonEventsResult_WithRules(t *testing.T) {
	info := sysmonInfo{
		Installed:   true,
		ServiceName: "Sysmon",
		Options:     0x01,
		RuleBytes:   8192,
	}
	result := sysmonEventsResult(info)
	if !strings.Contains(result.Output, "8192 bytes of custom rules") {
		t.Error("expected rules note")
	}
	if !strings.Contains(result.Output, "include/exclude rules") {
		t.Error("expected filter note")
	}
}
