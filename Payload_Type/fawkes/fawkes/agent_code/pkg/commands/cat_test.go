package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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

func TestCatJSONParams(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "json.txt")
	os.WriteFile(path, []byte("json param content"), 0644)

	cmd := &CatCommand{}
	task := structs.NewTask("t", "cat", "")
	params, _ := json.Marshal(catParams{Path: path})
	task.Params = string(params)
	result := cmd.Execute(task)
	if result.Status != "success" {
		t.Errorf("expected success, got %q: %s", result.Status, result.Output)
	}
	if result.Output != "json param content" {
		t.Errorf("expected 'json param content', got %q", result.Output)
	}
}

func TestCatJSONEmptyPath(t *testing.T) {
	cmd := &CatCommand{}
	task := structs.NewTask("t", "cat", "")
	params, _ := json.Marshal(catParams{Path: ""})
	task.Params = string(params)
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Errorf("expected error for empty path, got %q", result.Status)
	}
}

func TestCatDirectory(t *testing.T) {
	tmp := t.TempDir()

	cmd := &CatCommand{}
	task := structs.NewTask("t", "cat", "")
	task.Params = tmp
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Errorf("expected error for directory, got %q", result.Status)
	}
	if !strings.Contains(result.Output, "directory") {
		t.Errorf("expected directory error, got %q", result.Output)
	}
}

func TestCatSizeProtection(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "large.txt")
	// Create a file larger than default limit would allow with small max
	os.WriteFile(path, make([]byte, 2048), 0644)

	cmd := &CatCommand{}
	task := structs.NewTask("t", "cat", "")
	// Set max to 1KB
	params, _ := json.Marshal(catParams{Path: path, Max: 1})
	task.Params = string(params)
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Errorf("expected error for oversized file, got %q", result.Status)
	}
	if !strings.Contains(result.Output, "tail") {
		t.Errorf("expected suggestion to use tail, got %q", result.Output)
	}
}

func TestCatLineNumbers(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "numbered.txt")
	os.WriteFile(path, []byte("line1\nline2\nline3\n"), 0644)

	cmd := &CatCommand{}
	task := structs.NewTask("t", "cat", "")
	params, _ := json.Marshal(catParams{Path: path, Number: true})
	task.Params = string(params)
	result := cmd.Execute(task)
	if result.Status != "success" {
		t.Errorf("expected success, got %q: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "     1  line1") {
		t.Errorf("expected line numbers, got %q", result.Output)
	}
	if !strings.Contains(result.Output, "     3  line3") {
		t.Errorf("expected line 3 numbered, got %q", result.Output)
	}
	if !strings.Contains(result.Output, "3 lines") {
		t.Errorf("expected '3 lines' in header, got %q", result.Output)
	}
}

func TestCatLineRange(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "range.txt")
	var content strings.Builder
	for i := 1; i <= 20; i++ {
		content.WriteString(fmt.Sprintf("line %d\n", i))
	}
	os.WriteFile(path, []byte(content.String()), 0644)

	cmd := &CatCommand{}
	task := structs.NewTask("t", "cat", "")
	params, _ := json.Marshal(catParams{Path: path, Start: 5, End: 10})
	task.Params = string(params)
	result := cmd.Execute(task)
	if result.Status != "success" {
		t.Errorf("expected success, got %q: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "line 5") {
		t.Errorf("expected 'line 5', got %q", result.Output)
	}
	if !strings.Contains(result.Output, "line 10") {
		t.Errorf("expected 'line 10', got %q", result.Output)
	}
	if strings.Contains(result.Output, "line 4\n") {
		t.Errorf("should not contain line 4, got %q", result.Output)
	}
	if strings.Contains(result.Output, "line 11") {
		t.Errorf("should not contain line 11, got %q", result.Output)
	}
	if !strings.Contains(result.Output, "6 lines shown") {
		t.Errorf("expected '6 lines shown' in header, got %q", result.Output)
	}
}

func TestCatStartOnly(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "start.txt")
	os.WriteFile(path, []byte("line1\nline2\nline3\nline4\nline5\n"), 0644)

	cmd := &CatCommand{}
	task := structs.NewTask("t", "cat", "")
	params, _ := json.Marshal(catParams{Path: path, Start: 3})
	task.Params = string(params)
	result := cmd.Execute(task)
	if result.Status != "success" {
		t.Errorf("expected success, got %q: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "line3") {
		t.Errorf("expected 'line3', got %q", result.Output)
	}
	if !strings.Contains(result.Output, "line5") {
		t.Errorf("expected 'line5', got %q", result.Output)
	}
	if !strings.Contains(result.Output, "from line 3") {
		t.Errorf("expected 'from line 3' in header, got %q", result.Output)
	}
}

func TestCatEndOnly(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "end.txt")
	os.WriteFile(path, []byte("line1\nline2\nline3\nline4\nline5\n"), 0644)

	cmd := &CatCommand{}
	task := structs.NewTask("t", "cat", "")
	params, _ := json.Marshal(catParams{Path: path, End: 2})
	task.Params = string(params)
	result := cmd.Execute(task)
	if result.Status != "success" {
		t.Errorf("expected success, got %q: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "line1") {
		t.Errorf("expected 'line1', got %q", result.Output)
	}
	if !strings.Contains(result.Output, "line2") {
		t.Errorf("expected 'line2', got %q", result.Output)
	}
	if strings.Contains(result.Output, "line3") {
		t.Errorf("should not contain 'line3', got %q", result.Output)
	}
}

func TestCatLineRangeWithNumbers(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "range_num.txt")
	os.WriteFile(path, []byte("a\nb\nc\nd\ne\n"), 0644)

	cmd := &CatCommand{}
	task := structs.NewTask("t", "cat", "")
	params, _ := json.Marshal(catParams{Path: path, Start: 2, End: 4, Number: true})
	task.Params = string(params)
	result := cmd.Execute(task)
	if result.Status != "success" {
		t.Errorf("expected success, got %q: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "     2  b") {
		t.Errorf("expected numbered line 2, got %q", result.Output)
	}
	if !strings.Contains(result.Output, "     4  d") {
		t.Errorf("expected numbered line 4, got %q", result.Output)
	}
}

func TestCatOutputTruncation(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "truncate.txt")
	// Create file with many lines
	var content strings.Builder
	for i := 0; i < 1000; i++ {
		content.WriteString(strings.Repeat("x", 100) + "\n")
	}
	os.WriteFile(path, []byte(content.String()), 0644)

	cmd := &CatCommand{}
	task := structs.NewTask("t", "cat", "")
	// Use number=true to trigger line mode, max=1 (1KB)
	params, _ := json.Marshal(catParams{Path: path, Number: true, Max: 1})
	task.Params = string(params)
	result := cmd.Execute(task)
	if result.Status != "success" {
		t.Errorf("expected success, got %q: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "truncated") {
		t.Errorf("expected truncation notice, got length %d", len(result.Output))
	}
}

func TestCatEmptyFile(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "empty.txt")
	os.WriteFile(path, []byte{}, 0644)

	cmd := &CatCommand{}
	task := structs.NewTask("t", "cat", "")
	task.Params = path
	result := cmd.Execute(task)
	if result.Status != "success" {
		t.Errorf("expected success, got %q: %s", result.Status, result.Output)
	}
	if result.Output != "" {
		t.Errorf("expected empty output, got %q", result.Output)
	}
}

func TestCatBackwardCompatibility(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "compat.txt")
	os.WriteFile(path, []byte("backward compatible"), 0644)

	cmd := &CatCommand{}
	// Plain path string (backward compatible)
	task := structs.NewTask("t", "cat", "")
	task.Params = path
	result := cmd.Execute(task)
	if result.Status != "success" {
		t.Errorf("expected success, got %q: %s", result.Status, result.Output)
	}
	if result.Output != "backward compatible" {
		t.Errorf("expected 'backward compatible', got %q", result.Output)
	}
}

func TestCatReadFull(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "full.txt")
	os.WriteFile(path, []byte("full content"), 0644)

	result := catReadFull(path, maxCatBytes)
	if result.Status != "success" {
		t.Errorf("expected success, got %q", result.Status)
	}
	if result.Output != "full content" {
		t.Errorf("expected 'full content', got %q", result.Output)
	}
}

func TestCatReadFullNonexistent(t *testing.T) {
	result := catReadFull("/no/such/file", maxCatBytes)
	if result.Status != "error" {
		t.Errorf("expected error, got %q", result.Status)
	}
}

func TestCatReadFullDirectory(t *testing.T) {
	result := catReadFull(t.TempDir(), maxCatBytes)
	if result.Status != "error" {
		t.Errorf("expected error for directory, got %q", result.Status)
	}
}

func TestCatReadLinesNonexistent(t *testing.T) {
	result := catReadLines(catParams{Path: "/no/such/file", Number: true}, maxCatBytes)
	if result.Status != "error" {
		t.Errorf("expected error, got %q", result.Status)
	}
}
