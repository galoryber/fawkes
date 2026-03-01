package commands

import (
	"os"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestCdCommandName(t *testing.T) {
	cmd := &CdCommand{}
	if cmd.Name() != "cd" {
		t.Errorf("expected 'cd', got %q", cmd.Name())
	}
}

func TestCdCommandDescription(t *testing.T) {
	cmd := &CdCommand{}
	if cmd.Description() == "" {
		t.Error("description should not be empty")
	}
}

func TestCdNoParams(t *testing.T) {
	cmd := &CdCommand{}
	task := structs.NewTask("t", "cd", "")
	task.Params = ""
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Errorf("expected error status, got %q", result.Status)
	}
}

func TestCdWithStringPath(t *testing.T) {
	tmp := t.TempDir()
	// Save and restore cwd
	orig, _ := os.Getwd()
	defer os.Chdir(orig)

	cmd := &CdCommand{}
	task := structs.NewTask("t", "cd", "")
	task.Params = tmp
	result := cmd.Execute(task)
	if result.Status != "success" {
		t.Errorf("expected success, got %q: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, tmp) {
		t.Errorf("output should contain new path %q, got %q", tmp, result.Output)
	}
}

func TestCdWithJSONPath(t *testing.T) {
	tmp := t.TempDir()
	orig, _ := os.Getwd()
	defer os.Chdir(orig)

	cmd := &CdCommand{}
	task := structs.NewTask("t", "cd", "")
	task.Params = `{"path":"` + tmp + `"}`
	result := cmd.Execute(task)
	if result.Status != "success" {
		t.Errorf("expected success, got %q: %s", result.Status, result.Output)
	}
}

func TestCdNonexistentDir(t *testing.T) {
	cmd := &CdCommand{}
	task := structs.NewTask("t", "cd", "")
	task.Params = "/nonexistent/dir/path"
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Errorf("expected error status, got %q", result.Status)
	}
}

func TestCdEmptyJSONPath(t *testing.T) {
	cmd := &CdCommand{}
	task := structs.NewTask("t", "cd", "")
	task.Params = `{"path":""}`
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Errorf("expected error for empty JSON path, got %q", result.Status)
	}
}
