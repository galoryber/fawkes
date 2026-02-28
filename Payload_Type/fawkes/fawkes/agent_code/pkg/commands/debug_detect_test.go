package commands

import (
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestDebugDetectName(t *testing.T) {
	cmd := &DebugDetectCommand{}
	if cmd.Name() != "debug-detect" {
		t.Errorf("expected 'debug-detect', got %q", cmd.Name())
	}
}

func TestDebugDetectDescription(t *testing.T) {
	cmd := &DebugDetectCommand{}
	if cmd.Description() == "" {
		t.Error("description should not be empty")
	}
}

func TestDebugDetectExecuteDefault(t *testing.T) {
	cmd := &DebugDetectCommand{}
	task := structs.NewTask("t", "debug-detect", "")
	result := cmd.Execute(task)

	if result.Status != "success" {
		t.Fatalf("expected success, got %q: %s", result.Status, result.Output)
	}
	if !result.Completed {
		t.Error("expected Completed=true")
	}
	// Output should contain the results header
	if !strings.Contains(result.Output, "Debug Detection Results") {
		t.Errorf("expected output to contain 'Debug Detection Results', got: %s", result.Output)
	}
	// Should contain at least one check name (e.g., the process scan check)
	if !strings.Contains(result.Output, "Debugger Process Scan") {
		t.Errorf("expected output to contain 'Debugger Process Scan' check name, got: %s", result.Output)
	}
	// Should contain a summary line
	if !strings.Contains(result.Output, "CLEAN") && !strings.Contains(result.Output, "DETECTED") && !strings.Contains(result.Output, "WARNING") {
		t.Errorf("expected output to contain a status indicator (CLEAN/DETECTED/WARNING), got: %s", result.Output)
	}
}

func TestDebugDetectKnownProcessNames(t *testing.T) {
	// Verify the knownDebuggerProcesses map has entries
	if len(knownDebuggerProcesses) == 0 {
		t.Fatal("knownDebuggerProcesses map should not be empty")
	}
	// Check a few well-known entries exist
	expectedEntries := []string{"gdb", "lldb", "strace", "wireshark.exe", "x64dbg.exe"}
	for _, name := range expectedEntries {
		if _, ok := knownDebuggerProcesses[name]; !ok {
			t.Errorf("expected knownDebuggerProcesses to contain %q", name)
		}
	}
}
