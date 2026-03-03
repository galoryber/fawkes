package commands

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

// --- New tests for size, date, and type filtering ---

func TestFindMinSize(t *testing.T) {
	tmp := t.TempDir()
	os.WriteFile(filepath.Join(tmp, "small.txt"), []byte("x"), 0644)           // 1 byte
	os.WriteFile(filepath.Join(tmp, "big.txt"), make([]byte, 1024), 0644)      // 1 KB

	cmd := &FindCommand{}
	task := structs.NewTask("t", "find", "")
	task.Params = fmt.Sprintf(`{"path":"%s","pattern":"*.txt","min_size":512}`, tmp)
	result := cmd.Execute(task)
	if result.Status != "success" {
		t.Fatalf("expected success, got %q: %s", result.Status, result.Output)
	}
	if strings.Contains(result.Output, "small.txt") {
		t.Error("small.txt should be filtered out by min_size")
	}
	if !strings.Contains(result.Output, "big.txt") {
		t.Error("big.txt should match min_size filter")
	}
}

func TestFindMaxSize(t *testing.T) {
	tmp := t.TempDir()
	os.WriteFile(filepath.Join(tmp, "small.txt"), []byte("x"), 0644)           // 1 byte
	os.WriteFile(filepath.Join(tmp, "big.txt"), make([]byte, 2048), 0644)      // 2 KB

	cmd := &FindCommand{}
	task := structs.NewTask("t", "find", "")
	task.Params = fmt.Sprintf(`{"path":"%s","pattern":"*.txt","max_size":1024}`, tmp)
	result := cmd.Execute(task)
	if result.Status != "success" {
		t.Fatalf("expected success, got %q: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "small.txt") {
		t.Error("small.txt should match max_size filter")
	}
	if strings.Contains(result.Output, "big.txt") {
		t.Error("big.txt should be filtered out by max_size")
	}
}

func TestFindMinAndMaxSize(t *testing.T) {
	tmp := t.TempDir()
	os.WriteFile(filepath.Join(tmp, "tiny.txt"), []byte("x"), 0644)
	os.WriteFile(filepath.Join(tmp, "medium.txt"), make([]byte, 500), 0644)
	os.WriteFile(filepath.Join(tmp, "large.txt"), make([]byte, 2000), 0644)

	cmd := &FindCommand{}
	task := structs.NewTask("t", "find", "")
	task.Params = fmt.Sprintf(`{"path":"%s","pattern":"*.txt","min_size":100,"max_size":1000}`, tmp)
	result := cmd.Execute(task)
	if result.Status != "success" {
		t.Fatalf("expected success, got %q: %s", result.Status, result.Output)
	}
	if strings.Contains(result.Output, "tiny.txt") {
		t.Error("tiny.txt should be filtered out")
	}
	if !strings.Contains(result.Output, "medium.txt") {
		t.Error("medium.txt should match size range")
	}
	if strings.Contains(result.Output, "large.txt") {
		t.Error("large.txt should be filtered out")
	}
}

func TestFindTypeFilesOnly(t *testing.T) {
	tmp := t.TempDir()
	os.MkdirAll(filepath.Join(tmp, "subdir"), 0755)
	os.WriteFile(filepath.Join(tmp, "file.txt"), []byte("x"), 0644)

	cmd := &FindCommand{}
	task := structs.NewTask("t", "find", "")
	task.Params = fmt.Sprintf(`{"path":"%s","pattern":"*","type":"f"}`, tmp)
	result := cmd.Execute(task)
	if result.Status != "success" {
		t.Fatalf("expected success, got %q: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "file.txt") {
		t.Error("should include files")
	}
	if strings.Contains(result.Output, "subdir") {
		t.Error("should exclude directories with type=f")
	}
}

func TestFindTypeDirsOnly(t *testing.T) {
	tmp := t.TempDir()
	os.MkdirAll(filepath.Join(tmp, "subdir"), 0755)
	os.WriteFile(filepath.Join(tmp, "file.txt"), []byte("x"), 0644)

	cmd := &FindCommand{}
	task := structs.NewTask("t", "find", "")
	task.Params = fmt.Sprintf(`{"path":"%s","pattern":"*","type":"d"}`, tmp)
	result := cmd.Execute(task)
	if result.Status != "success" {
		t.Fatalf("expected success, got %q: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "subdir") {
		t.Error("should include directories")
	}
	if strings.Contains(result.Output, "file.txt") {
		t.Error("should exclude files with type=d")
	}
}

func TestFindNewer(t *testing.T) {
	tmp := t.TempDir()
	// Create a file modified "now" (within last 5 minutes)
	os.WriteFile(filepath.Join(tmp, "new.txt"), []byte("x"), 0644)
	// Create a file and set its mtime to 2 hours ago
	oldFile := filepath.Join(tmp, "old.txt")
	os.WriteFile(oldFile, []byte("y"), 0644)
	twoHoursAgo := time.Now().Add(-2 * time.Hour)
	os.Chtimes(oldFile, twoHoursAgo, twoHoursAgo)

	cmd := &FindCommand{}
	task := structs.NewTask("t", "find", "")
	task.Params = fmt.Sprintf(`{"path":"%s","pattern":"*.txt","newer":60}`, tmp)
	result := cmd.Execute(task)
	if result.Status != "success" {
		t.Fatalf("expected success, got %q: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "new.txt") {
		t.Error("new.txt should match newer=60 (modified within last 60 minutes)")
	}
	if strings.Contains(result.Output, "old.txt") {
		t.Error("old.txt should be filtered out by newer=60")
	}
}

func TestFindOlder(t *testing.T) {
	tmp := t.TempDir()
	os.WriteFile(filepath.Join(tmp, "new.txt"), []byte("x"), 0644)
	oldFile := filepath.Join(tmp, "old.txt")
	os.WriteFile(oldFile, []byte("y"), 0644)
	twoHoursAgo := time.Now().Add(-2 * time.Hour)
	os.Chtimes(oldFile, twoHoursAgo, twoHoursAgo)

	cmd := &FindCommand{}
	task := structs.NewTask("t", "find", "")
	task.Params = fmt.Sprintf(`{"path":"%s","pattern":"*.txt","older":60}`, tmp)
	result := cmd.Execute(task)
	if result.Status != "success" {
		t.Fatalf("expected success, got %q: %s", result.Status, result.Output)
	}
	if strings.Contains(result.Output, "new.txt") {
		t.Error("new.txt should be filtered out by older=60")
	}
	if !strings.Contains(result.Output, "old.txt") {
		t.Error("old.txt should match older=60 (modified more than 60 minutes ago)")
	}
}

func TestFindOutputIncludesTimestamp(t *testing.T) {
	tmp := t.TempDir()
	os.WriteFile(filepath.Join(tmp, "test.txt"), []byte("x"), 0644)

	cmd := &FindCommand{}
	task := structs.NewTask("t", "find", "")
	task.Params = fmt.Sprintf(`{"path":"%s","pattern":"*.txt"}`, tmp)
	result := cmd.Execute(task)
	if result.Status != "success" {
		t.Fatalf("expected success, got %q: %s", result.Status, result.Output)
	}
	// Output should now include timestamp in YYYY-MM-DD HH:MM format
	year := time.Now().Format("2006")
	if !strings.Contains(result.Output, year) {
		t.Error("output should include modification timestamp")
	}
}

func TestFindDefaultPatternWithFilters(t *testing.T) {
	// When filters are set but no pattern, should default to "*"
	tmp := t.TempDir()
	os.WriteFile(filepath.Join(tmp, "test.txt"), []byte("x"), 0644)

	cmd := &FindCommand{}
	task := structs.NewTask("t", "find", "")
	task.Params = fmt.Sprintf(`{"path":"%s","type":"f"}`, tmp)
	result := cmd.Execute(task)
	if result.Status == "error" && strings.Contains(result.Output, "pattern is required") {
		t.Error("should not require pattern when filters are set")
	}
	if !strings.Contains(result.Output, "test.txt") {
		t.Error("should find files with default pattern")
	}
}

func TestFindFilterSummary(t *testing.T) {
	params := FindParams{
		MaxDepth: 5,
		MinSize:  1024,
		Type:     "f",
	}
	summary := findFilterSummary(params)
	if !strings.Contains(summary, "depth=5") {
		t.Error("should include depth in summary")
	}
	if !strings.Contains(summary, "min_size=1.0 KB") {
		t.Error("should include min_size in summary")
	}
	if !strings.Contains(summary, "type=f") {
		t.Error("should include type in summary")
	}
}

func TestFindFilterSummaryNoFilters(t *testing.T) {
	params := FindParams{MaxDepth: 10} // default depth
	summary := findFilterSummary(params)
	if summary != "" {
		t.Errorf("should return empty string when no filters active, got %q", summary)
	}
}
