package commands

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestLsCommandName(t *testing.T) {
	cmd := &LsCommand{}
	if cmd.Name() != "ls" {
		t.Errorf("expected 'ls', got %q", cmd.Name())
	}
}

func TestLsDefaultsToCurrentDir(t *testing.T) {
	cmd := &LsCommand{}
	task := structs.NewTask("t", "ls", "")
	task.Params = ""
	result := cmd.Execute(task)
	if result.Status != "success" {
		t.Errorf("expected success, got %q: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "Contents of directory") {
		t.Errorf("expected directory listing output, got %q", result.Output)
	}
}

func TestLsSpecificDir(t *testing.T) {
	tmp := t.TempDir()
	os.WriteFile(filepath.Join(tmp, "file1.txt"), []byte("a"), 0644)
	os.Mkdir(filepath.Join(tmp, "subdir"), 0755)

	cmd := &LsCommand{}
	task := structs.NewTask("t", "ls", "")
	task.Params = tmp
	result := cmd.Execute(task)
	if result.Status != "success" {
		t.Errorf("expected success, got %q: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "file1.txt") {
		t.Error("output should contain file1.txt")
	}
	if !strings.Contains(result.Output, "subdir") {
		t.Error("output should contain subdir")
	}
}

func TestLsFileBrowserMode(t *testing.T) {
	tmp := t.TempDir()
	os.WriteFile(filepath.Join(tmp, "test.txt"), []byte("x"), 0644)

	cmd := &LsCommand{}
	task := structs.NewTask("t", "ls", "")
	task.Params = `{"path":"` + tmp + `","file_browser":true}`
	result := cmd.Execute(task)
	if result.Status != "success" {
		t.Errorf("expected success, got %q: %s", result.Status, result.Output)
	}

	// Should be valid JSON
	var listing structs.FileListing
	if err := json.Unmarshal([]byte(result.Output), &listing); err != nil {
		t.Errorf("file_browser output should be valid JSON: %v", err)
	}
	if !listing.Success {
		t.Error("listing should be successful")
	}
}

func TestLsNonexistentDir(t *testing.T) {
	cmd := &LsCommand{}
	task := structs.NewTask("t", "ls", "")
	task.Params = "/nonexistent/directory"
	result := cmd.Execute(task)
	// ls returns success with Success=false in the output
	if result.Status != "success" {
		t.Errorf("expected success status, got %q", result.Status)
	}
	if !strings.Contains(result.Output, "Failed") {
		t.Error("output should indicate failure for nonexistent directory")
	}
}

func TestLsSingleFile(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "single.txt")
	os.WriteFile(path, []byte("content"), 0644)

	cmd := &LsCommand{}
	task := structs.NewTask("t", "ls", "")
	task.Params = `{"path":"` + path + `","file_browser":true}`
	result := cmd.Execute(task)
	if result.Status != "success" {
		t.Fatalf("expected success, got %q: %s", result.Status, result.Output)
	}

	var listing structs.FileListing
	json.Unmarshal([]byte(result.Output), &listing)
	if !listing.IsFile {
		t.Error("should indicate IsFile=true for a single file")
	}
}

func TestPerformLsDirectory(t *testing.T) {
	tmp := t.TempDir()
	os.WriteFile(filepath.Join(tmp, "a.txt"), []byte("a"), 0644)
	os.WriteFile(filepath.Join(tmp, "b.txt"), []byte("bb"), 0644)

	result := performLs(tmp)
	if !result.Success {
		t.Error("performLs should succeed")
	}
	if len(result.Files) != 2 {
		t.Errorf("expected 2 files, got %d", len(result.Files))
	}
}

func TestFormatLsOutputFailure(t *testing.T) {
	result := structs.FileListing{Success: false, ParentPath: "/bad"}
	output := formatLsOutput(result)
	if !strings.Contains(output, "Failed") {
		t.Error("should indicate failure")
	}
}

func TestGetHostname(t *testing.T) {
	h := getHostname()
	if h == "" {
		t.Error("hostname should not be empty")
	}
}
