package commands

import (
	"encoding/json"
	"testing"

	"fawkes/pkg/structs"
)

func TestDfReturnsJSON(t *testing.T) {
	cmd := &DfCommand{}
	result := cmd.Execute(structs.Task{Params: ""})

	if result.Status != "success" {
		t.Fatalf("expected success, got %s: %s", result.Status, result.Output)
	}
	var entries []dfOutputEntry
	if err := json.Unmarshal([]byte(result.Output), &entries); err != nil {
		t.Fatalf("expected valid JSON output: %v (got: %s)", err, result.Output)
	}
	if len(entries) == 0 {
		t.Fatal("expected at least one filesystem entry")
	}
	// Check first entry has a mount point
	if entries[0].MountPoint == "" {
		t.Error("expected non-empty mount point")
	}
}

func TestTruncStr(t *testing.T) {
	if truncStr("hello", 10) != "hello" {
		t.Fatal("short string should not be truncated")
	}
	result := truncStr("verylongstring", 5)
	if len(result) > 5 {
		t.Fatalf("expected max 5 chars, got %d: %s", len(result), result)
	}
}
