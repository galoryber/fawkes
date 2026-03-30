//go:build darwin

package commands

import (
	"os"
	"testing"
)

func TestReadProcessEnvironSelf(t *testing.T) {
	pid := os.Getpid()
	envVars, processName, err := readProcessEnviron(pid)
	if err != nil {
		t.Fatalf("readProcessEnviron(self) failed: %v", err)
	}
	if processName == "" {
		t.Error("expected non-empty process name")
	}
	if len(envVars) == 0 {
		t.Error("expected at least one environment variable for self")
	}
	// Should find PATH in env vars
	foundPath := false
	for _, v := range envVars {
		if len(v) > 5 && v[:5] == "PATH=" {
			foundPath = true
			break
		}
	}
	if !foundPath {
		t.Error("expected PATH in environment variables")
	}
}

func TestReadProcessEnvironInvalidPID(t *testing.T) {
	_, _, err := readProcessEnviron(999999999)
	if err == nil {
		t.Error("expected error for invalid PID")
	}
}

func TestListAllPIDs(t *testing.T) {
	pids, err := listAllPIDs()
	if err != nil {
		t.Fatalf("listAllPIDs failed: %v", err)
	}
	if len(pids) == 0 {
		t.Error("expected at least one PID")
	}
	// Should contain our own PID
	myPID := os.Getpid()
	found := false
	for _, pid := range pids {
		if pid == myPID {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected to find own PID in list")
	}
}

func TestDeduplicateResults(t *testing.T) {
	results := []envScanResult{
		{Variable: "KEY1", Value: "val1", PID: 1, Process: "a"},
		{Variable: "KEY1", Value: "val1", PID: 2, Process: "b"},
		{Variable: "KEY2", Value: "val2", PID: 1, Process: "a"},
	}
	deduped := deduplicateResults(results)
	if len(deduped) != 2 {
		t.Errorf("expected 2 unique results, got %d", len(deduped))
	}
}

func TestEnvScanAllProcesses(t *testing.T) {
	result := envScanAllProcesses("")
	assertSuccess(t, result)
}

func TestEnvScanAllProcessesFiltered(t *testing.T) {
	result := envScanAllProcesses("zzz_nonexistent_xyz")
	assertSuccess(t, result)
}
