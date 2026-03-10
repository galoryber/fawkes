//go:build linux

package commands

import (
	"os"
	"strconv"
	"testing"
)

func TestDeduplicateResults_Empty(t *testing.T) {
	result := deduplicateResults(nil)
	if result != nil {
		t.Errorf("expected nil, got %v", result)
	}
}

func TestDeduplicateResults_NoDuplicates(t *testing.T) {
	input := []envScanResult{
		{PID: 1, Process: "bash", Variable: "AWS_SECRET", Value: "val1", Category: "AWS Credential"},
		{PID: 2, Process: "python", Variable: "DB_PASSWORD", Value: "val2", Category: "Database Password"},
	}
	result := deduplicateResults(input)
	if len(result) != 2 {
		t.Fatalf("expected 2 results, got %d", len(result))
	}
}

func TestDeduplicateResults_WithDuplicates(t *testing.T) {
	input := []envScanResult{
		{PID: 1, Process: "bash", Variable: "AWS_SECRET", Value: "same_val", Category: "AWS Credential"},
		{PID: 2, Process: "bash-child", Variable: "AWS_SECRET", Value: "same_val", Category: "AWS Credential"},
		{PID: 3, Process: "python", Variable: "AWS_SECRET", Value: "different_val", Category: "AWS Credential"},
		{PID: 4, Process: "bash-grandchild", Variable: "AWS_SECRET", Value: "same_val", Category: "AWS Credential"},
	}
	result := deduplicateResults(input)
	if len(result) != 2 {
		t.Fatalf("expected 2 deduplicated results, got %d", len(result))
	}
	// First occurrence should be kept
	if result[0].PID != 1 {
		t.Errorf("expected first occurrence PID 1, got %d", result[0].PID)
	}
	if result[1].PID != 3 {
		t.Errorf("expected different-value PID 3, got %d", result[1].PID)
	}
}

func TestDeduplicateResults_SameVariableDifferentValues(t *testing.T) {
	input := []envScanResult{
		{PID: 1, Variable: "SECRET", Value: "aaa", Category: "Secret"},
		{PID: 2, Variable: "SECRET", Value: "bbb", Category: "Secret"},
		{PID: 3, Variable: "SECRET", Value: "ccc", Category: "Secret"},
	}
	result := deduplicateResults(input)
	if len(result) != 3 {
		t.Fatalf("expected 3 (different values), got %d", len(result))
	}
}

func TestReadProcessEnviron_Self(t *testing.T) {
	pid := os.Getpid()
	envVars, processName, err := readProcessEnviron(pid)
	if err != nil {
		t.Fatalf("readProcessEnviron(self) failed: %v", err)
	}

	if processName == "" {
		t.Error("expected non-empty process name")
	}

	if len(envVars) == 0 {
		t.Error("expected non-empty environment variables")
	}

	// Our process should have PATH set
	found := false
	for _, kv := range envVars {
		if len(kv) > 5 && kv[:5] == "PATH=" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected to find PATH in process environment")
	}
}

func TestReadProcessEnviron_Nonexistent(t *testing.T) {
	// PID that almost certainly doesn't exist
	_, _, err := readProcessEnviron(4000000)
	if err == nil {
		t.Error("expected error for nonexistent PID")
	}
}

func TestReadProcessEnviron_ProcessName(t *testing.T) {
	pid := os.Getpid()
	_, processName, err := readProcessEnviron(pid)
	if err != nil {
		t.Fatalf("readProcessEnviron(self) failed: %v", err)
	}

	// Process name should be non-empty and not the fallback format
	if processName == "pid-"+strconv.Itoa(pid) {
		t.Error("process name should come from /proc/pid/comm, not fallback")
	}
}
