package commands

import (
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestDfBasic(t *testing.T) {
	cmd := &DfCommand{}
	result := cmd.Execute(structs.Task{Params: ""})

	if result.Status != "success" {
		t.Fatalf("expected success, got %s: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "Filesystem") {
		t.Fatalf("expected header, got: %s", result.Output)
	}
	// Should have at least one filesystem
	if !strings.Contains(result.Output, "/") && !strings.Contains(result.Output, "\\") {
		t.Fatalf("expected at least one mount point, got: %s", result.Output)
	}
}

func TestDfHasSize(t *testing.T) {
	cmd := &DfCommand{}
	result := cmd.Execute(structs.Task{Params: ""})

	if result.Status != "success" {
		t.Fatalf("expected success, got %s: %s", result.Status, result.Output)
	}
	// Should show size information
	if !strings.Contains(result.Output, "Size") {
		t.Fatalf("expected Size header, got: %s", result.Output)
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
