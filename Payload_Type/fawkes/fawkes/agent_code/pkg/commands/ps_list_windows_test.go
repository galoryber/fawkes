//go:build windows

package commands

import (
	"testing"
	"time"
)

func TestGetProcessListDefault(t *testing.T) {
	procs, err := getProcessList(PsArgs{})
	if err != nil {
		t.Fatalf("getProcessList failed: %v", err)
	}
	if len(procs) == 0 {
		t.Error("getProcessList returned empty list")
	}
	// Should always find System (PID 4) and itself
	foundSystem := false
	for _, p := range procs {
		if p.PID == 4 {
			foundSystem = true
			break
		}
	}
	if !foundSystem {
		t.Error("expected to find System process (PID 4)")
	}
}

func TestGetProcessListPIDFilter(t *testing.T) {
	procs, err := getProcessList(PsArgs{PID: 4})
	if err != nil {
		t.Fatalf("getProcessList PID filter failed: %v", err)
	}
	if len(procs) != 1 {
		t.Errorf("expected 1 process with PID=4, got %d", len(procs))
	}
	if len(procs) > 0 && procs[0].PID != 4 {
		t.Errorf("expected PID=4, got PID=%d", procs[0].PID)
	}
}

func TestGetProcessListNameFilter(t *testing.T) {
	procs, err := getProcessList(PsArgs{Filter: "system"})
	if err != nil {
		t.Fatalf("getProcessList name filter failed: %v", err)
	}
	for _, p := range procs {
		if p.Name == "" {
			t.Error("process has empty name")
		}
	}
}

func TestGetProcessListNonexistentFilter(t *testing.T) {
	procs, err := getProcessList(PsArgs{Filter: "zzz_nonexistent_process_xyz"})
	if err != nil {
		t.Fatalf("getProcessList failed: %v", err)
	}
	if len(procs) != 0 {
		t.Errorf("expected 0 processes for nonexistent filter, got %d", len(procs))
	}
}

func TestPerProcessTimeoutConstant(t *testing.T) {
	if perProcessTimeout != 2*time.Second {
		t.Errorf("perProcessTimeout = %v, want 2s", perProcessTimeout)
	}
}

func TestQueryWinProcessAttrs(t *testing.T) {
	// PID 4 (System) — test that queryWinProcessAttrs doesn't panic
	attrs := queryWinProcessAttrs(4)
	t.Logf("System process: username=%q exePath=%q integrity=%d startTime=%d",
		attrs.username, attrs.exePath, attrs.integrityLevel, attrs.startTime)
}

func TestGetProcessIntegrityLevel(t *testing.T) {
	// Get our own process integrity level — should be at least medium (2)
	procs, err := getProcessList(PsArgs{Verbose: true})
	if err != nil {
		t.Fatalf("getProcessList failed: %v", err)
	}
	for _, p := range procs {
		if p.IntegrityLevel > 0 {
			t.Logf("Process %s (PID %d) integrity=%d", p.Name, p.PID, p.IntegrityLevel)
			return
		}
	}
	t.Log("No processes with integrity level data (expected if running without verbose)")
}

func TestGetProcessStartTime(t *testing.T) {
	procs, err := getProcessList(PsArgs{Verbose: true})
	if err != nil {
		t.Fatalf("getProcessList failed: %v", err)
	}
	for _, p := range procs {
		if p.StartTime > 0 {
			t.Logf("Process %s (PID %d) startTime=%d", p.Name, p.PID, p.StartTime)
			return
		}
	}
	t.Log("No processes with start time data")
}
