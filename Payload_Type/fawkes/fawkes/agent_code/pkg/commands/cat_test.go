package commands

import (
	"os"
	"path/filepath"
	"testing"

	"fawkes/pkg/structs"
)

func TestCatCommandName(t *testing.T) {
	cmd := &CatCommand{}
	if cmd.Name() != "cat" {
		t.Errorf("expected 'cat', got %q", cmd.Name())
	}
}

func TestCatCommandDescription(t *testing.T) {
	cmd := &CatCommand{}
	if cmd.Description() == "" {
		t.Error("description should not be empty")
	}
}

func TestCatNoParams(t *testing.T) {
	cmd := &CatCommand{}
	task := structs.NewTask("t", "cat", "")
	task.Params = ""
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Errorf("expected error status, got %q", result.Status)
	}
}

func TestCatReadFile(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "test.txt")
	os.WriteFile(path, []byte("hello world"), 0644)

	cmd := &CatCommand{}
	task := structs.NewTask("t", "cat", "")
	task.Params = path
	result := cmd.Execute(task)
	if result.Status != "success" {
		t.Errorf("expected success, got %q: %s", result.Status, result.Output)
	}
	if result.Output != "hello world" {
		t.Errorf("expected 'hello world', got %q", result.Output)
	}
}

func TestCatNonexistentFile(t *testing.T) {
	cmd := &CatCommand{}
	task := structs.NewTask("t", "cat", "")
	task.Params = "/nonexistent/file/path"
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Errorf("expected error status, got %q", result.Status)
	}
}

func TestCatStripQuotes(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "quoted.txt")
	os.WriteFile(path, []byte("quoted content"), 0644)

	cmd := &CatCommand{}
	task := structs.NewTask("t", "cat", "")
	task.Params = `"` + path + `"`
	result := cmd.Execute(task)
	if result.Status != "success" {
		t.Errorf("expected success with quoted path, got %q: %s", result.Status, result.Output)
	}
}
