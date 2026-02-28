package commands

import (
	"fawkes/pkg/structs"
	"testing"
)

func TestDownloadName(t *testing.T) {
	cmd := &DownloadCommand{}
	if cmd.Name() != "download" {
		t.Errorf("expected 'download', got '%s'", cmd.Name())
	}
}

func TestDownloadDescription(t *testing.T) {
	cmd := &DownloadCommand{}
	if cmd.Description() == "" {
		t.Error("description should not be empty")
	}
}

func TestDownloadEmptyPath(t *testing.T) {
	cmd := &DownloadCommand{}
	result := cmd.Execute(structs.Task{Params: ""})
	if result.Status != "error" {
		t.Errorf("expected error for empty path, got '%s'", result.Status)
	}
	if !result.Completed {
		t.Error("should be completed on error")
	}
}

func TestDownloadNonexistentFile(t *testing.T) {
	cmd := &DownloadCommand{}
	result := cmd.Execute(structs.Task{Params: "/nonexistent/path/file.txt"})
	if result.Status != "error" {
		t.Errorf("expected error for nonexistent file, got '%s'", result.Status)
	}
}

func TestDownloadQuotedPath(t *testing.T) {
	cmd := &DownloadCommand{}
	// Path with quotes should still fail gracefully for nonexistent file
	result := cmd.Execute(structs.Task{Params: `"/nonexistent/path/file.txt"`})
	if result.Status != "error" {
		t.Errorf("expected error for nonexistent quoted path, got '%s'", result.Status)
	}
}
