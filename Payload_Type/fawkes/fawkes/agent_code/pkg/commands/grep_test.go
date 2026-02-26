package commands

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestGrepCommand_Name(t *testing.T) {
	cmd := &GrepCommand{}
	if cmd.Name() != "grep" {
		t.Errorf("expected 'grep', got %q", cmd.Name())
	}
}

func TestGrepCommand_NoParams(t *testing.T) {
	cmd := &GrepCommand{}
	result := cmd.Execute(structs.Task{Params: ""})
	if result.Status != "error" {
		t.Error("expected error for no params")
	}
}

func TestGrepCommand_InvalidJSON(t *testing.T) {
	cmd := &GrepCommand{}
	result := cmd.Execute(structs.Task{Params: "not json"})
	if result.Status != "error" {
		t.Error("expected error for invalid JSON")
	}
}

func TestGrepCommand_EmptyPattern(t *testing.T) {
	cmd := &GrepCommand{}
	params, _ := json.Marshal(grepArgs{Pattern: ""})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Error("expected error for empty pattern")
	}
}

func TestGrepCommand_InvalidRegex(t *testing.T) {
	cmd := &GrepCommand{}
	params, _ := json.Marshal(grepArgs{Pattern: "[invalid"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Error("expected error for invalid regex")
	}
	if !strings.Contains(result.Output, "invalid regex") {
		t.Errorf("expected regex error message, got: %s", result.Output)
	}
}

func TestGrepCommand_SearchSingleFile(t *testing.T) {
	// Create a temp file with known content
	dir := t.TempDir()
	testFile := filepath.Join(dir, "test.txt")
	content := "line one\nline two has PASSWORD=secret\nline three\nline four has PASSWORD=other\nline five\n"
	if err := os.WriteFile(testFile, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	cmd := &GrepCommand{}
	params, _ := json.Marshal(grepArgs{Pattern: "PASSWORD", Path: testFile})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Fatalf("expected success, got: %s", result.Output)
	}
	if !strings.Contains(result.Output, "2 matches") {
		t.Errorf("expected 2 matches, got: %s", result.Output)
	}
	if !strings.Contains(result.Output, "PASSWORD=secret") {
		t.Error("expected to find PASSWORD=secret in output")
	}
}

func TestGrepCommand_SearchDirectory(t *testing.T) {
	dir := t.TempDir()

	// Create files
	os.WriteFile(filepath.Join(dir, "config.txt"), []byte("db_password=mypass123\nother_line\n"), 0644)
	os.WriteFile(filepath.Join(dir, "readme.md"), []byte("no secrets here\njust docs\n"), 0644)
	os.MkdirAll(filepath.Join(dir, "subdir"), 0755)
	os.WriteFile(filepath.Join(dir, "subdir", "app.conf"), []byte("api_key=ABC123\ndb_password=prod456\n"), 0644)

	cmd := &GrepCommand{}
	params, _ := json.Marshal(grepArgs{Pattern: "password", Path: dir, IgnoreCase: true})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Fatalf("expected success, got: %s", result.Output)
	}
	if !strings.Contains(result.Output, "db_password") {
		t.Error("expected to find db_password in output")
	}
}

func TestGrepCommand_ExtensionFilter(t *testing.T) {
	dir := t.TempDir()

	os.WriteFile(filepath.Join(dir, "keep.txt"), []byte("TARGET_LINE\n"), 0644)
	os.WriteFile(filepath.Join(dir, "skip.log"), []byte("TARGET_LINE\n"), 0644)
	os.WriteFile(filepath.Join(dir, "keep2.txt"), []byte("no match\n"), 0644)

	cmd := &GrepCommand{}
	params, _ := json.Marshal(grepArgs{Pattern: "TARGET_LINE", Path: dir, Extensions: ".txt"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Fatalf("expected success, got: %s", result.Output)
	}
	if !strings.Contains(result.Output, "1 matches") {
		t.Errorf("expected exactly 1 match (only .txt), got: %s", result.Output)
	}
}

func TestGrepCommand_IgnoreCase(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "test.txt"), []byte("Hello World\nhello world\nHELLO WORLD\n"), 0644)

	cmd := &GrepCommand{}

	// Case sensitive
	params, _ := json.Marshal(grepArgs{Pattern: "Hello", Path: dir})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Fatal(result.Output)
	}
	if !strings.Contains(result.Output, "1 matches") {
		t.Errorf("case-sensitive should find 1 match, got: %s", result.Output)
	}

	// Case insensitive
	params, _ = json.Marshal(grepArgs{Pattern: "Hello", Path: dir, IgnoreCase: true})
	result = cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Fatal(result.Output)
	}
	if !strings.Contains(result.Output, "3 matches") {
		t.Errorf("case-insensitive should find 3 matches, got: %s", result.Output)
	}
}

func TestGrepCommand_MaxResults(t *testing.T) {
	dir := t.TempDir()
	// Create file with many matches
	var lines []string
	for i := 0; i < 50; i++ {
		lines = append(lines, "match_line_here")
	}
	os.WriteFile(filepath.Join(dir, "many.txt"), []byte(strings.Join(lines, "\n")), 0644)

	cmd := &GrepCommand{}
	params, _ := json.Marshal(grepArgs{Pattern: "match_line", Path: dir, MaxResults: 5})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Fatal(result.Output)
	}
	if !strings.Contains(result.Output, "truncated") {
		t.Error("expected truncation notice")
	}
	// Count actual match lines (lines with "match_line" in output)
	matchCount := strings.Count(result.Output, "match_line_here")
	if matchCount > 5 {
		t.Errorf("expected at most 5 results, got %d", matchCount)
	}
}

func TestGrepCommand_ContextLines(t *testing.T) {
	dir := t.TempDir()
	content := "line1\nline2\nline3\nTARGET\nline5\nline6\n"
	os.WriteFile(filepath.Join(dir, "ctx.txt"), []byte(content), 0644)

	cmd := &GrepCommand{}
	params, _ := json.Marshal(grepArgs{Pattern: "TARGET", Path: dir, Context: 2})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Fatal(result.Output)
	}
	// Should include context lines before the match
	if !strings.Contains(result.Output, "line2") {
		t.Error("expected context line 'line2' in output")
	}
	if !strings.Contains(result.Output, "line3") {
		t.Error("expected context line 'line3' in output")
	}
}

func TestGrepCommand_NoMatches(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "empty.txt"), []byte("nothing interesting\n"), 0644)

	cmd := &GrepCommand{}
	params, _ := json.Marshal(grepArgs{Pattern: "NONEXISTENT_PATTERN_12345", Path: dir})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Error("expected success even with no matches")
	}
	if !strings.Contains(result.Output, "No matches found") {
		t.Errorf("expected 'No matches found', got: %s", result.Output)
	}
}

func TestGrepCommand_BinaryExtension(t *testing.T) {
	// Verify binary extension detection
	binExts := []string{".exe", ".dll", ".so", ".png", ".jpg", ".zip", ".pdf"}
	for _, ext := range binExts {
		if !isBinaryExtension(ext) {
			t.Errorf("expected %s to be detected as binary", ext)
		}
	}

	textExts := []string{".txt", ".go", ".py", ".xml", ".json", ".yaml", ".ini", ".conf", ".sh"}
	for _, ext := range textExts {
		if isBinaryExtension(ext) {
			t.Errorf("expected %s to NOT be detected as binary", ext)
		}
	}
}

func TestGrepCommand_InvalidPath(t *testing.T) {
	cmd := &GrepCommand{}
	params, _ := json.Marshal(grepArgs{Pattern: "test", Path: "/nonexistent/path/xyz"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Error("expected error for nonexistent path")
	}
}

func TestGrepCommand_RegexSupport(t *testing.T) {
	dir := t.TempDir()
	content := "password=abc123\nPASSWORD=XYZ789\nuser=admin\napi_key=sk-1234567890\n"
	os.WriteFile(filepath.Join(dir, "config.txt"), []byte(content), 0644)

	cmd := &GrepCommand{}
	// Regex: match lines with key=value where value starts with letters then digits
	params, _ := json.Marshal(grepArgs{Pattern: `=\w+\d{3,}`, Path: dir})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Fatal(result.Output)
	}
	if !strings.Contains(result.Output, "password=abc123") {
		t.Error("expected regex to match 'password=abc123'")
	}
}

func TestGrepCommand_SkipsHiddenDirs(t *testing.T) {
	dir := t.TempDir()

	// Create visible file with match
	os.WriteFile(filepath.Join(dir, "visible.txt"), []byte("FINDME\n"), 0644)

	// Create hidden dir with match
	hiddenDir := filepath.Join(dir, ".hidden")
	os.MkdirAll(hiddenDir, 0755)
	os.WriteFile(filepath.Join(hiddenDir, "secret.txt"), []byte("FINDME\n"), 0644)

	cmd := &GrepCommand{}
	params, _ := json.Marshal(grepArgs{Pattern: "FINDME", Path: dir})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Fatal(result.Output)
	}
	// Should find 1 match (visible only), not 2
	if !strings.Contains(result.Output, "1 matches") {
		t.Errorf("expected 1 match (hidden dir skipped), got: %s", result.Output)
	}
}

func TestSearchFile(t *testing.T) {
	dir := t.TempDir()
	testFile := filepath.Join(dir, "test.txt")
	os.WriteFile(testFile, []byte("alpha\nbeta\ngamma\ndelta\n"), 0644)

	re, _ := regexp.Compile("beta|delta")
	matches := searchFile(testFile, re, 0, 100)
	if len(matches) != 2 {
		t.Fatalf("expected 2 matches, got %d", len(matches))
	}
	if matches[0].Line != 2 || matches[0].Content != "beta" {
		t.Errorf("match 0: expected line 2 'beta', got line %d %q", matches[0].Line, matches[0].Content)
	}
	if matches[1].Line != 4 || matches[1].Content != "delta" {
		t.Errorf("match 1: expected line 4 'delta', got line %d %q", matches[1].Line, matches[1].Content)
	}
}
