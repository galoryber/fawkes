package commands

import (
	"os"
	"path/filepath"
	"testing"

	"fawkes/pkg/structs"
)

func TestMvCommandName(t *testing.T) {
	cmd := &MvCommand{}
	if cmd.Name() != "mv" {
		t.Errorf("expected 'mv', got %q", cmd.Name())
	}
}

func TestMvNoParams(t *testing.T) {
	cmd := &MvCommand{}
	task := structs.NewTask("t", "mv", "")
	task.Params = ""
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Errorf("expected error, got %q", result.Status)
	}
}

func TestMvMissingSource(t *testing.T) {
	cmd := &MvCommand{}
	task := structs.NewTask("t", "mv", "")
	task.Params = `{"source":"","destination":"/tmp/dest"}`
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Errorf("expected error, got %q", result.Status)
	}
}

func TestMvSuccess(t *testing.T) {
	tmp := t.TempDir()
	src := filepath.Join(tmp, "original.txt")
	dst := filepath.Join(tmp, "moved.txt")
	os.WriteFile(src, []byte("move me"), 0644)

	cmd := &MvCommand{}
	task := structs.NewTask("t", "mv", "")
	task.Params = `{"source":"` + src + `","destination":"` + dst + `"}`
	result := cmd.Execute(task)
	if result.Status != "success" {
		t.Errorf("expected success, got %q: %s", result.Status, result.Output)
	}

	// Source should no longer exist
	if _, err := os.Stat(src); !os.IsNotExist(err) {
		t.Error("source file should no longer exist")
	}

	// Destination should exist with correct content
	content, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("dest should exist: %v", err)
	}
	if string(content) != "move me" {
		t.Errorf("expected 'move me', got %q", string(content))
	}
}

func TestMvNonexistentSource(t *testing.T) {
	tmp := t.TempDir()
	cmd := &MvCommand{}
	task := structs.NewTask("t", "mv", "")
	task.Params = `{"source":"/nonexistent","destination":"` + filepath.Join(tmp, "dest") + `"}`
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Errorf("expected error for nonexistent source, got %q", result.Status)
	}
}

func TestMvBadJSON(t *testing.T) {
	cmd := &MvCommand{}
	task := structs.NewTask("t", "mv", "")
	task.Params = `not json`
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Errorf("expected error for bad JSON, got %q", result.Status)
	}
}
