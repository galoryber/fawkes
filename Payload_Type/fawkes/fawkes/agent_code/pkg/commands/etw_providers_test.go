//go:build windows
// +build windows

package commands

import (
	"encoding/json"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestEtwProviderDisable_RequiresSessionName(t *testing.T) {
	result := etwProviderDisable("", "process")
	if result.Status != "error" {
		t.Errorf("Expected error for empty session_name, got %s", result.Status)
	}
	if !strings.Contains(result.Output, "session_name is required") {
		t.Errorf("Expected session_name required message, got %q", result.Output)
	}
}

func TestEtwProviderDisable_RequiresProvider(t *testing.T) {
	result := etwProviderDisable("TestSession", "")
	if result.Status != "error" {
		t.Errorf("Expected error for empty provider, got %s", result.Status)
	}
	if !strings.Contains(result.Output, "provider is required") {
		t.Errorf("Expected provider required message, got %q", result.Output)
	}
}

func TestEtwProviderDisable_UnknownFlag(t *testing.T) {
	result := etwProviderDisable("TestSession", "nonexistent-flag")
	if result.Status != "error" {
		t.Errorf("Expected error for unknown flag, got %s", result.Status)
	}
	if !strings.Contains(result.Output, "Unknown kernel flag") {
		t.Errorf("Expected unknown kernel flag message, got %q", result.Output)
	}
	// Should suggest using blind for user-mode providers
	if !strings.Contains(result.Output, "blind") {
		t.Errorf("Expected suggestion to use blind, got %q", result.Output)
	}
}

func TestEtwProviderEnable_RequiresSessionName(t *testing.T) {
	result := etwProviderEnable("", "process")
	if result.Status != "error" {
		t.Errorf("Expected error for empty session_name, got %s", result.Status)
	}
}

func TestEtwProviderEnable_RequiresProvider(t *testing.T) {
	result := etwProviderEnable("TestSession", "")
	if result.Status != "error" {
		t.Errorf("Expected error for empty provider, got %s", result.Status)
	}
}

func TestEtwProviderEnable_UnknownFlag(t *testing.T) {
	result := etwProviderEnable("TestSession", "bogus")
	if result.Status != "error" {
		t.Errorf("Expected error for unknown flag, got %s", result.Status)
	}
}

func TestEtw_ProviderDisableViaDispatch(t *testing.T) {
	cmd := &EtwCommand{}
	params, _ := json.Marshal(etwParams{Action: "provider-disable"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("provider-disable without args should error, got %s", result.Status)
	}
}

func TestEtw_ProviderEnableViaDispatch(t *testing.T) {
	cmd := &EtwCommand{}
	params, _ := json.Marshal(etwParams{Action: "provider-enable"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("provider-enable without args should error, got %s", result.Status)
	}
}

func TestEtw_ProviderListViaDispatch(t *testing.T) {
	cmd := &EtwCommand{}
	params, _ := json.Marshal(etwParams{Action: "provider-list"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	// This will either succeed (on a Windows system with ETW) or fail gracefully
	// Just ensure no panic
	_ = result
}

func TestFormatKernelFlags_Empty(t *testing.T) {
	result := formatKernelFlags(0)
	if result != "(none)" {
		t.Errorf("Expected '(none)' for 0 flags, got %q", result)
	}
}

func TestFormatKernelFlags_Single(t *testing.T) {
	result := formatKernelFlags(eventTraceFlagProcess)
	if !strings.Contains(result, "Process") {
		t.Errorf("Expected 'Process' in output, got %q", result)
	}
}

func TestFormatKernelFlags_Multiple(t *testing.T) {
	result := formatKernelFlags(eventTraceFlagProcess | eventTraceFlagNetworkTCPIP)
	if !strings.Contains(result, "Process") || !strings.Contains(result, "Network") {
		t.Errorf("Expected Process and Network in output, got %q", result)
	}
}

func TestKernelFlagNames_AllValid(t *testing.T) {
	for name, flag := range kernelFlagNames {
		if flag == 0 {
			t.Errorf("Flag %q should not be zero", name)
		}
		// Verify it has a display name
		if _, ok := kernelFlagDisplayNames[flag]; !ok {
			t.Errorf("Flag %q (0x%X) has no display name", name, flag)
		}
	}
}

func TestClassifyProviderCategory(t *testing.T) {
	tests := []struct {
		name     string
		expected string
	}{
		{"Microsoft-Windows-Kernel-Process", "Kernel"},
		{"Microsoft-Windows-Sysmon", "EDR"},
		{"Microsoft-Antimalware-Scan-Interface", "AV/AMSI"},
		{"Microsoft-Windows-PowerShell", "Runtime"},
		{"Microsoft-Windows-DotNETRuntime", "Runtime"},
		{"Microsoft-Windows-Security-Auditing", "Audit"},
		{"Microsoft-Windows-WinRM", "Remote"},
		{"Microsoft-Windows-WMI-Activity", "Remote"},
		{"Microsoft-Windows-DNS-Client", "Network"},
		{"Microsoft-Windows-LDAP-Client", "Network"},
		{"Microsoft-Windows-CAPI2", "Auth"},
		{"Microsoft-Windows-Winlogon", "Auth"},
		{"Microsoft-Windows-TaskScheduler", "Sched"},
		{"SomeRandomProvider", "Other"},
	}
	for _, tt := range tests {
		got := classifyProviderCategory(tt.name)
		if got != tt.expected {
			t.Errorf("classifyProviderCategory(%q) = %q, want %q", tt.name, got, tt.expected)
		}
	}
}

func TestEtwLevelName(t *testing.T) {
	tests := []struct {
		level    int
		expected string
	}{
		{0, "NONE"},
		{1, "CRITICAL"},
		{2, "ERROR"},
		{3, "WARNING"},
		{4, "INFO"},
		{5, "VERBOSE"},
		{6, "LEVEL_6"},
		{255, "LEVEL_255"},
	}
	for _, tt := range tests {
		got := etwLevelName(tt.level)
		if got != tt.expected {
			t.Errorf("etwLevelName(%d) = %q, want %q", tt.level, got, tt.expected)
		}
	}
}

func TestParseProviderInstanceInfo_EmptyData(t *testing.T) {
	info := providerInfo{Name: "test", GUID: "TEST-GUID"}
	result := parseProviderInstanceInfo(nil, info)
	if result.Instances != 0 {
		t.Errorf("Expected 0 instances for nil data, got %d", result.Instances)
	}
	if len(result.Sessions) != 0 {
		t.Errorf("Expected 0 sessions for nil data, got %d", len(result.Sessions))
	}
}

func TestParseProviderInstanceInfo_ShortData(t *testing.T) {
	data := make([]byte, 4) // too short for TRACE_GUID_INFO
	info := providerInfo{Name: "test"}
	result := parseProviderInstanceInfo(data, info)
	if result.Instances != 0 {
		t.Errorf("Expected 0 instances for short data, got %d", result.Instances)
	}
}

func TestParseProviderInstanceInfo_ZeroInstances(t *testing.T) {
	data := make([]byte, 8)
	// InstanceCount = 0
	info := providerInfo{Name: "test"}
	result := parseProviderInstanceInfo(data, info)
	if result.Instances != 0 {
		t.Errorf("Expected 0 instances, got %d", result.Instances)
	}
}

func TestParseProviderInstanceInfo_OneInstance(t *testing.T) {
	// Build TRACE_GUID_INFO + TRACE_PROVIDER_INSTANCE_INFO + TRACE_ENABLE_INFO
	data := make([]byte, 8+16+24) // header + instance + enable

	// TRACE_GUID_INFO: InstanceCount=1, Reserved=0
	data[0] = 1

	// TRACE_PROVIDER_INSTANCE_INFO at offset 8:
	// NextOffset=0, EnableCount=1, Pid=1234, Flags=0
	data[12] = 1 // EnableCount = 1
	data[16] = 0xD2
	data[17] = 0x04 // Pid = 1234

	// TRACE_ENABLE_INFO at offset 24:
	// IsEnabled=1, Level=5(VERBOSE), Reserved1=0, LoggerId=2, EnableProperty=0, MatchAnyKeyword=0xFF
	data[24] = 1    // IsEnabled
	data[28] = 5    // Level = VERBOSE
	data[30] = 2    // LoggerId = 2
	data[36] = 0xFF // MatchAnyKeyword low byte

	info := providerInfo{Name: "test"}
	result := parseProviderInstanceInfo(data, info)
	if result.Instances != 1 {
		t.Errorf("Expected 1 instance, got %d", result.Instances)
	}
	if len(result.Sessions) != 1 {
		t.Fatalf("Expected 1 session, got %d", len(result.Sessions))
	}
	if result.Sessions[0].LoggerID != 2 {
		t.Errorf("Expected LoggerID 2, got %d", result.Sessions[0].LoggerID)
	}
	if result.Sessions[0].Level != 5 {
		t.Errorf("Expected Level 5, got %d", result.Sessions[0].Level)
	}
}
