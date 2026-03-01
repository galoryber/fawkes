package commands

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestTacBasic(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "data.txt")
	os.WriteFile(f, []byte("line1\nline2\nline3\n"), 0644)

	params, _ := json.Marshal(tacArgs{Path: f})
	cmd := &TacCommand{}
	result := cmd.Execute(structs.Task{Params: string(params)})

	if result.Status != "success" {
		t.Fatalf("expected success, got %s: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "3 lines") {
		t.Fatalf("expected 3 lines, got: %s", result.Output)
	}
	// First data line should be line3 (reversed)
	lines := strings.Split(result.Output, "\n")
	for _, l := range lines {
		if strings.TrimSpace(l) == "line3" {
			return // found line3 before line1
		}
		if strings.TrimSpace(l) == "line1" {
			t.Fatalf("line1 appeared before line3 in reversed output")
		}
	}
}

func TestTacSingleLine(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "data.txt")
	os.WriteFile(f, []byte("only line\n"), 0644)

	params, _ := json.Marshal(tacArgs{Path: f})
	cmd := &TacCommand{}
	result := cmd.Execute(structs.Task{Params: string(params)})

	if result.Status != "success" {
		t.Fatalf("expected success, got %s: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "only line") {
		t.Fatalf("expected 'only line', got: %s", result.Output)
	}
}

func TestTacNonexistent(t *testing.T) {
	params, _ := json.Marshal(tacArgs{Path: "/nonexistent/file.txt"})
	cmd := &TacCommand{}
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Fatalf("expected error, got %s", result.Status)
	}
}

func TestTacNoParams(t *testing.T) {
	cmd := &TacCommand{}
	result := cmd.Execute(structs.Task{Params: ""})
	if result.Status != "error" {
		t.Fatalf("expected error, got %s", result.Status)
	}
}

func TestTacEmptyPath(t *testing.T) {
	params, _ := json.Marshal(tacArgs{Path: ""})
	cmd := &TacCommand{}
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Fatalf("expected error, got %s", result.Status)
	}
}
