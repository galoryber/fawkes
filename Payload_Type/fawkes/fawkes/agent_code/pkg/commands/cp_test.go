package commands

import (
	"os"
	"path/filepath"
	"testing"

	"fawkes/pkg/structs"
)

func TestCpCommandName(t *testing.T) {
	cmd := &CpCommand{}
	if cmd.Name() != "cp" {
		t.Errorf("expected 'cp', got %q", cmd.Name())
	}
}

func TestCpNoParams(t *testing.T) {
	cmd := &CpCommand{}
	task := structs.NewTask("t", "cp", "")
	task.Params = ""
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Errorf("expected error, got %q", result.Status)
	}
}

func TestCpMissingSource(t *testing.T) {
	cmd := &CpCommand{}
	task := structs.NewTask("t", "cp", "")
	task.Params = `{"source":"","destination":"/tmp/dest"}`
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Errorf("expected error for missing source, got %q", result.Status)
	}
}

func TestCpMissingDest(t *testing.T) {
	cmd := &CpCommand{}
	task := structs.NewTask("t", "cp", "")
	task.Params = `{"source":"/tmp/src","destination":""}`
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Errorf("expected error for missing dest, got %q", result.Status)
	}
}

func TestCpSuccess(t *testing.T) {
	tmp := t.TempDir()
	src := filepath.Join(tmp, "source.txt")
	dst := filepath.Join(tmp, "dest.txt")
	os.WriteFile(src, []byte("copy me"), 0644)

	cmd := &CpCommand{}
	task := structs.NewTask("t", "cp", "")
	task.Params = `{"source":"` + src + `","destination":"` + dst + `"}`
	result := cmd.Execute(task)
	if result.Status != "success" {
		t.Errorf("expected success, got %q: %s", result.Status, result.Output)
	}

	content, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("failed to read dest: %v", err)
	}
	if string(content) != "copy me" {
		t.Errorf("expected 'copy me', got %q", string(content))
	}
}

func TestCpNonexistentSource(t *testing.T) {
	tmp := t.TempDir()
	cmd := &CpCommand{}
	task := structs.NewTask("t", "cp", "")
	task.Params = `{"source":"/nonexistent","destination":"` + filepath.Join(tmp, "dest") + `"}`
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Errorf("expected error for nonexistent source, got %q", result.Status)
	}
}

func TestCpDirectorySource(t *testing.T) {
	tmp := t.TempDir()
	dir := filepath.Join(tmp, "srcdir")
	os.Mkdir(dir, 0755)

	cmd := &CpCommand{}
	task := structs.NewTask("t", "cp", "")
	task.Params = `{"source":"` + dir + `","destination":"` + filepath.Join(tmp, "dest") + `"}`
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Errorf("expected error for directory source, got %q", result.Status)
	}
}

func TestCpPreservesPermissions(t *testing.T) {
	tmp := t.TempDir()
	src := filepath.Join(tmp, "exec.sh")
	dst := filepath.Join(tmp, "exec_copy.sh")
	os.WriteFile(src, []byte("#!/bin/sh"), 0755)

	cmd := &CpCommand{}
	task := structs.NewTask("t", "cp", "")
	task.Params = `{"source":"` + src + `","destination":"` + dst + `"}`
	result := cmd.Execute(task)
	if result.Status != "success" {
		t.Fatalf("expected success, got %q: %s", result.Status, result.Output)
	}

	info, _ := os.Stat(dst)
	if info.Mode().Perm() != 0755 {
		t.Errorf("expected 0755 permissions, got %o", info.Mode().Perm())
	}
}
