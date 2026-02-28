package commands

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestRmCommandName(t *testing.T) {
	cmd := &RmCommand{}
	if cmd.Name() != "rm" {
		t.Errorf("expected 'rm', got %q", cmd.Name())
	}
}

func TestRmNoParams(t *testing.T) {
	cmd := &RmCommand{}
	task := structs.NewTask("t", "rm", "")
	task.Params = ""
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Errorf("expected error, got %q", result.Status)
	}
}

func TestRmFile(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "deleteme.txt")
	os.WriteFile(path, []byte("x"), 0644)

	cmd := &RmCommand{}
	task := structs.NewTask("t", "rm", "")
	task.Params = path
	result := cmd.Execute(task)
	if result.Status != "success" {
		t.Errorf("expected success, got %q: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "file") {
		t.Error("output should mention file type")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("file should be deleted")
	}
}

func TestRmDirectory(t *testing.T) {
	tmp := t.TempDir()
	dir := filepath.Join(tmp, "deldir")
	os.MkdirAll(filepath.Join(dir, "sub"), 0755)
	os.WriteFile(filepath.Join(dir, "sub", "file.txt"), []byte("x"), 0644)

	cmd := &RmCommand{}
	task := structs.NewTask("t", "rm", "")
	task.Params = dir
	result := cmd.Execute(task)
	if result.Status != "success" {
		t.Errorf("expected success, got %q: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "directory") {
		t.Error("output should mention directory type")
	}
}

func TestRmNonexistent(t *testing.T) {
	cmd := &RmCommand{}
	task := structs.NewTask("t", "rm", "")
	task.Params = "/nonexistent/path"
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Errorf("expected error, got %q", result.Status)
	}
}

func TestRmJSONParams(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "jsonrm.txt")
	os.WriteFile(path, []byte("x"), 0644)

	cmd := &RmCommand{}
	task := structs.NewTask("t", "rm", "")
	task.Params = `{"path":"` + path + `"}`
	result := cmd.Execute(task)
	if result.Status != "success" {
		t.Errorf("expected success with JSON params, got %q: %s", result.Status, result.Output)
	}
}
