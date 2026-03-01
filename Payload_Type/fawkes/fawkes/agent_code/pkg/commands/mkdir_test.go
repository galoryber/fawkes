package commands

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestMkdirCommandName(t *testing.T) {
	cmd := &MkdirCommand{}
	if cmd.Name() != "mkdir" {
		t.Errorf("expected 'mkdir', got %q", cmd.Name())
	}
}

func TestMkdirNoParams(t *testing.T) {
	cmd := &MkdirCommand{}
	task := structs.NewTask("t", "mkdir", "")
	task.Params = ""
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Errorf("expected error, got %q", result.Status)
	}
}

func TestMkdirSuccess(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "newdir")

	cmd := &MkdirCommand{}
	task := structs.NewTask("t", "mkdir", "")
	task.Params = path
	result := cmd.Execute(task)
	if result.Status != "success" {
		t.Errorf("expected success, got %q: %s", result.Status, result.Output)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("directory should exist: %v", err)
	}
	if !info.IsDir() {
		t.Error("should be a directory")
	}
}

func TestMkdirJSONParams(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "jsondir")

	cmd := &MkdirCommand{}
	task := structs.NewTask("t", "mkdir", "")
	task.Params = `{"path":"` + path + `"}`
	result := cmd.Execute(task)
	if result.Status != "success" {
		t.Errorf("expected success, got %q: %s", result.Status, result.Output)
	}

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("directory should exist: %v", err)
	}
}

func TestMkdirNestedDirs(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "a", "b", "c")

	cmd := &MkdirCommand{}
	task := structs.NewTask("t", "mkdir", "")
	task.Params = path
	result := cmd.Execute(task)
	if result.Status != "success" {
		t.Errorf("expected success for nested dirs, got %q: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "Successfully") {
		t.Error("output should indicate success")
	}
}
