package agentfunctions

import (
	"testing"
)

func TestIntegrityLabel(t *testing.T) {
	tests := []struct {
		level    int
		expected string
	}{
		{0, ""},
		{1, ""},
		{2, "Medium"},
		{3, "Admin"},
		{4, "SYSTEM"},
		{5, "SYSTEM"},
	}
	for _, tt := range tests {
		got := integrityLabel(tt.level)
		if got != tt.expected {
			t.Errorf("integrityLabel(%d) = %q, want %q", tt.level, got, tt.expected)
		}
	}
}

func TestWindowsAutoLoadCommands_UserLevel(t *testing.T) {
	cmds := windowsAutoLoadCommands(2) // Medium integrity
	if len(cmds) == 0 {
		t.Fatal("Expected at least one command for user-level")
	}
	// Should NOT include elevated commands
	for _, cmd := range cmds {
		if cmd == "hashdump" || cmd == "lsa-secrets" || cmd == "getsystem" {
			t.Errorf("User-level should not auto-load %q", cmd)
		}
	}
}

func TestWindowsAutoLoadCommands_Elevated(t *testing.T) {
	cmds := windowsAutoLoadCommands(4) // SYSTEM
	// Should include elevated commands
	hasHashdump := false
	for _, cmd := range cmds {
		if cmd == "hashdump" {
			hasHashdump = true
		}
	}
	if !hasHashdump {
		t.Error("SYSTEM-level should auto-load hashdump")
	}
}

func TestLinuxAutoLoadCommands_UserLevel(t *testing.T) {
	cmds := linuxAutoLoadCommands(2)
	for _, cmd := range cmds {
		if cmd == "ptrace-inject" {
			t.Error("User-level Linux should not auto-load ptrace-inject")
		}
	}
}

func TestLinuxAutoLoadCommands_Root(t *testing.T) {
	cmds := linuxAutoLoadCommands(4)
	hasPtrace := false
	for _, cmd := range cmds {
		if cmd == "ptrace-inject" {
			hasPtrace = true
		}
	}
	if !hasPtrace {
		t.Error("Root-level Linux should auto-load ptrace-inject")
	}
}

func TestMacosAutoLoadCommands(t *testing.T) {
	cmds := macosAutoLoadCommands()
	if len(cmds) == 0 {
		t.Fatal("Expected at least one command for macOS")
	}
}
