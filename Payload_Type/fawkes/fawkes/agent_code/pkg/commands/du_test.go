package commands

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestDuSingleFile(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "test.txt")
	os.WriteFile(tmp, []byte("hello world"), 0644)

	cmd := &DuCommand{}
	params, _ := json.Marshal(duArgs{Path: tmp})
	result := cmd.Execute(structs.Task{Params: string(params)})

	if result.Status != "success" {
		t.Fatalf("expected success: %s", result.Output)
	}
	if !strings.Contains(result.Output, "11 bytes") || !strings.Contains(result.Output, "11 B") {
		t.Errorf("expected 11 bytes in output: %s", result.Output)
	}
}

func TestDuDirectory(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "a.txt"), make([]byte, 1000), 0644)
	os.WriteFile(filepath.Join(dir, "b.txt"), make([]byte, 2000), 0644)
	os.MkdirAll(filepath.Join(dir, "sub"), 0755)
	os.WriteFile(filepath.Join(dir, "sub", "c.txt"), make([]byte, 500), 0644)

	cmd := &DuCommand{}
	params, _ := json.Marshal(duArgs{Path: dir})
	result := cmd.Execute(structs.Task{Params: string(params)})

	if result.Status != "success" {
		t.Fatalf("expected success: %s", result.Output)
	}
	if !strings.Contains(result.Output, "3 files") {
		t.Errorf("expected 3 files: %s", result.Output)
	}
	if !strings.Contains(result.Output, "3.4 KB") {
		t.Errorf("expected ~3.4 KB total: %s", result.Output)
	}
}

func TestDuEmptyDirectory(t *testing.T) {
	dir := t.TempDir()

	cmd := &DuCommand{}
	params, _ := json.Marshal(duArgs{Path: dir})
	result := cmd.Execute(structs.Task{Params: string(params)})

	if result.Status != "success" {
		t.Fatalf("expected success: %s", result.Output)
	}
	if !strings.Contains(result.Output, "0 files") {
		t.Errorf("expected 0 files: %s", result.Output)
	}
}

func TestDuNonexistent(t *testing.T) {
	cmd := &DuCommand{}
	params, _ := json.Marshal(duArgs{Path: "/tmp/nonexistent_du_test"})
	result := cmd.Execute(structs.Task{Params: string(params)})

	if result.Status != "error" {
		t.Errorf("expected error: %s", result.Status)
	}
}

func TestDuNoParams(t *testing.T) {
	cmd := &DuCommand{}
	result := cmd.Execute(structs.Task{Params: ""})
	if result.Status != "error" {
		t.Errorf("expected error with no params")
	}
}

func TestDuEmptyPath(t *testing.T) {
	cmd := &DuCommand{}
	params, _ := json.Marshal(duArgs{Path: ""})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error with empty path")
	}
}

func TestDuSortedBySize(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "small"), 0755)
	os.MkdirAll(filepath.Join(dir, "large"), 0755)
	os.WriteFile(filepath.Join(dir, "small", "a.txt"), make([]byte, 100), 0644)
	os.WriteFile(filepath.Join(dir, "large", "b.txt"), make([]byte, 5000), 0644)

	cmd := &DuCommand{}
	params, _ := json.Marshal(duArgs{Path: dir})
	result := cmd.Execute(structs.Task{Params: string(params)})

	if result.Status != "success" {
		t.Fatalf("expected success: %s", result.Output)
	}
	// "large" should appear before "small" in output (sorted by size desc)
	largeIdx := strings.Index(result.Output, "large")
	smallIdx := strings.Index(result.Output, "small")
	if largeIdx == -1 || smallIdx == -1 || largeIdx > smallIdx {
		t.Errorf("expected large before small (sorted by size desc): %s", result.Output)
	}
}
