package commands

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestFindCommandName(t *testing.T) {
	cmd := &FindCommand{}
	if cmd.Name() != "find" {
		t.Errorf("expected 'find', got %q", cmd.Name())
	}
}

func TestFindMissingPattern(t *testing.T) {
	cmd := &FindCommand{}
	task := structs.NewTask("t", "find", "")
	task.Params = `{"path":"/tmp","pattern":""}`
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Errorf("expected error for missing pattern, got %q", result.Status)
	}
}

func TestFindSuccess(t *testing.T) {
	tmp := t.TempDir()
	os.WriteFile(filepath.Join(tmp, "test.txt"), []byte("x"), 0644)
	os.WriteFile(filepath.Join(tmp, "test.log"), []byte("y"), 0644)

	cmd := &FindCommand{}
	task := structs.NewTask("t", "find", "")
	task.Params = `{"path":"` + tmp + `","pattern":"*.txt"}`
	result := cmd.Execute(task)
	if result.Status != "success" {
		t.Errorf("expected success, got %q: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "test.txt") {
		t.Error("output should contain test.txt")
	}
	if strings.Contains(result.Output, "test.log") {
		t.Error("output should not contain test.log")
	}
}

func TestFindNoMatches(t *testing.T) {
	tmp := t.TempDir()

	cmd := &FindCommand{}
	task := structs.NewTask("t", "find", "")
	task.Params = `{"path":"` + tmp + `","pattern":"*.xyz"}`
	result := cmd.Execute(task)
	if result.Status != "success" {
		t.Errorf("expected success, got %q", result.Status)
	}
	if !strings.Contains(result.Output, "No files matching") {
		t.Error("should report no matches")
	}
}

func TestFindMaxDepth(t *testing.T) {
	tmp := t.TempDir()
	deep := filepath.Join(tmp, "a", "b", "c")
	os.MkdirAll(deep, 0755)
	os.WriteFile(filepath.Join(deep, "deep.txt"), []byte("x"), 0644)
	os.WriteFile(filepath.Join(tmp, "shallow.txt"), []byte("y"), 0644)

	cmd := &FindCommand{}
	task := structs.NewTask("t", "find", "")
	task.Params = `{"path":"` + tmp + `","pattern":"*.txt","max_depth":1}`
	result := cmd.Execute(task)
	if result.Status != "success" {
		t.Errorf("expected success, got %q: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "shallow.txt") {
		t.Error("should find shallow.txt within depth 1")
	}
	if strings.Contains(result.Output, "deep.txt") {
		t.Error("should not find deep.txt beyond max_depth=1")
	}
}

func TestFindDefaultPath(t *testing.T) {
	cmd := &FindCommand{}
	task := structs.NewTask("t", "find", "")
	task.Params = `{"pattern":"*.go"}`
	result := cmd.Execute(task)
	// Should succeed even without explicit path (defaults to ".")
	if result.Status != "success" {
		t.Errorf("expected success with default path, got %q", result.Status)
	}
}

func TestFindCancellation(t *testing.T) {
	cmd := &FindCommand{}
	task := structs.NewTask("t", "find", "")
	task.Params = `{"path":"/","pattern":"*","max_depth":1}`
	task.SetStop()
	result := cmd.Execute(task)
	// Should complete (possibly with partial results) without hanging
	if !result.Completed {
		t.Error("should complete even when cancelled")
	}
}

func TestFindPlainText(t *testing.T) {
	cmd := &FindCommand{}
	task := structs.NewTask("t", "find", "")
	task.Params = "*.go"
	result := cmd.Execute(task)
	// Plain text should be treated as pattern (not a parse error)
	if result.Status == "error" && strings.Contains(result.Output, "Error parsing") {
		t.Errorf("plain text should be treated as pattern, got parse error: %s", result.Output)
	}
}

func TestFindFormatFileSize(t *testing.T) {
	tests := []struct {
		bytes    int64
		expected string
	}{
		{500, "500 B"},
		{1024, "1.0 KB"},
		{1536, "1.5 KB"},
		{1048576, "1.0 MB"},
		{1073741824, "1.0 GB"},
	}
	for _, tc := range tests {
		result := formatFileSize(tc.bytes)
		if result != tc.expected {
			t.Errorf("formatFileSize(%d) = %q, want %q", tc.bytes, result, tc.expected)
		}
	}
}
