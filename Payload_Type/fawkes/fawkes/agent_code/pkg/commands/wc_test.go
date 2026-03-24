package commands

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestWcSingleFile(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "test.txt")
	os.WriteFile(tmp, []byte("hello world\nfoo bar baz\n"), 0644)

	cmd := &WcCommand{}
	params, _ := json.Marshal(wcArgs{Path: tmp})
	result := cmd.Execute(structs.Task{Params: string(params)})

	if result.Status != "success" {
		t.Fatalf("expected success: %s", result.Output)
	}
	if !strings.Contains(result.Output, "Lines: 2") {
		t.Errorf("expected 2 lines: %s", result.Output)
	}
	if !strings.Contains(result.Output, "Words: 5") {
		t.Errorf("expected 5 words: %s", result.Output)
	}
}

func TestWcEmptyFile(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "empty.txt")
	os.WriteFile(tmp, []byte{}, 0644)

	cmd := &WcCommand{}
	params, _ := json.Marshal(wcArgs{Path: tmp})
	result := cmd.Execute(structs.Task{Params: string(params)})

	if result.Status != "success" {
		t.Fatalf("expected success: %s", result.Output)
	}
	if !strings.Contains(result.Output, "Lines: 0") {
		t.Errorf("expected 0 lines: %s", result.Output)
	}
	if !strings.Contains(result.Output, "Words: 0") {
		t.Errorf("expected 0 words: %s", result.Output)
	}
}

func TestWcSingleLine(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "single.txt")
	os.WriteFile(tmp, []byte("one two three\n"), 0644)

	cmd := &WcCommand{}
	params, _ := json.Marshal(wcArgs{Path: tmp})
	result := cmd.Execute(structs.Task{Params: string(params)})

	if result.Status != "success" {
		t.Fatalf("expected success: %s", result.Output)
	}
	if !strings.Contains(result.Output, "Lines: 1") {
		t.Errorf("expected 1 line: %s", result.Output)
	}
	if !strings.Contains(result.Output, "Words: 3") {
		t.Errorf("expected 3 words: %s", result.Output)
	}
}

func TestWcDirectory(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "a.txt"), []byte("hello\nworld\n"), 0644)
	os.WriteFile(filepath.Join(dir, "b.txt"), []byte("foo bar\n"), 0644)

	cmd := &WcCommand{}
	params, _ := json.Marshal(wcArgs{Path: dir})
	result := cmd.Execute(structs.Task{Params: string(params)})

	if result.Status != "success" {
		t.Fatalf("expected success: %s", result.Output)
	}
	if !strings.Contains(result.Output, "2 files") {
		t.Errorf("expected 2 files: %s", result.Output)
	}
	if !strings.Contains(result.Output, "total") {
		t.Errorf("expected total line: %s", result.Output)
	}
}

func TestWcDirectoryPattern(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "a.txt"), []byte("hello\n"), 0644)
	os.WriteFile(filepath.Join(dir, "b.log"), []byte("log data\n"), 0644)
	os.WriteFile(filepath.Join(dir, "c.txt"), []byte("world\n"), 0644)

	cmd := &WcCommand{}
	params, _ := json.Marshal(wcArgs{Path: dir, Pattern: "*.txt"})
	result := cmd.Execute(structs.Task{Params: string(params)})

	if result.Status != "success" {
		t.Fatalf("expected success: %s", result.Output)
	}
	if !strings.Contains(result.Output, "2 files") {
		t.Errorf("expected 2 files (only .txt): %s", result.Output)
	}
}

func TestWcNonexistent(t *testing.T) {
	cmd := &WcCommand{}
	params, _ := json.Marshal(wcArgs{Path: "/tmp/nonexistent_wc_test"})
	result := cmd.Execute(structs.Task{Params: string(params)})

	if result.Status != "error" {
		t.Errorf("expected error: %s", result.Status)
	}
}

func TestWcNoParams(t *testing.T) {
	cmd := &WcCommand{}
	result := cmd.Execute(structs.Task{Params: ""})
	if result.Status != "error" {
		t.Errorf("expected error with no params")
	}
}

func TestWcEmptyPath(t *testing.T) {
	cmd := &WcCommand{}
	params, _ := json.Marshal(wcArgs{Path: ""})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error with empty path")
	}
}

func TestCountWords(t *testing.T) {
	tests := []struct {
		input    string
		expected int
	}{
		{"", 0},
		{"hello", 1},
		{"hello world", 2},
		{"  hello   world  ", 2},
		{"one\ttwo\tthree", 3},
	}
	for _, tt := range tests {
		got := countWords(tt.input)
		if got != tt.expected {
			t.Errorf("countWords(%q) = %d, want %d", tt.input, got, tt.expected)
		}
	}
}

func TestWcBytes(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "bytes.txt")
	content := []byte("hello\n")
	os.WriteFile(tmp, content, 0644)

	cmd := &WcCommand{}
	params, _ := json.Marshal(wcArgs{Path: tmp})
	result := cmd.Execute(structs.Task{Params: string(params)})

	if result.Status != "success" {
		t.Fatalf("expected success: %s", result.Output)
	}
	if !strings.Contains(result.Output, "Bytes: 6") {
		t.Errorf("expected 6 bytes: %s", result.Output)
	}
}

func TestWcRawStringParams(t *testing.T) {
	// Test that raw (non-JSON) string params are accepted as a path
	tmp := filepath.Join(t.TempDir(), "raw.txt")
	os.WriteFile(tmp, []byte("a b c\n"), 0644)

	cmd := &WcCommand{}
	result := cmd.Execute(structs.Task{Params: tmp})

	if result.Status != "success" {
		t.Fatalf("expected success with raw path: %s", result.Output)
	}
	if !strings.Contains(result.Output, "Words: 3") {
		t.Errorf("expected 3 words: %s", result.Output)
	}
}

func TestWcDirectorySingleFile(t *testing.T) {
	// With a single file, the "total" summary line should not appear
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "only.txt"), []byte("hello world\n"), 0644)

	cmd := &WcCommand{}
	params, _ := json.Marshal(wcArgs{Path: dir})
	result := cmd.Execute(structs.Task{Params: string(params)})

	if result.Status != "success" {
		t.Fatalf("expected success: %s", result.Output)
	}
	if !strings.Contains(result.Output, "1 files") {
		t.Errorf("expected 1 file: %s", result.Output)
	}
	if strings.Contains(result.Output, "total") {
		t.Errorf("single-file directory should not show total: %s", result.Output)
	}
}

func TestWcFilePermissionDenied(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "noperm.txt")
	os.WriteFile(tmp, []byte("secret\n"), 0644)
	os.Chmod(tmp, 0000)
	defer os.Chmod(tmp, 0644)

	_, err := wcFile(tmp)
	if err == nil {
		t.Error("expected error for permission-denied file")
	}
}

func TestCountWordsCarriageReturn(t *testing.T) {
	// \r is treated as whitespace
	got := countWords("one\rtwo\rthree")
	if got != 3 {
		t.Errorf("countWords with \\r = %d, want 3", got)
	}
}

func TestFormatWcResult(t *testing.T) {
	r := wcResult{path: "/tmp/test.txt", lines: 10, words: 50, chars: 200, bytes: 250}
	out := formatWcResult(r)
	if !strings.Contains(out, "/tmp/test.txt") {
		t.Error("missing path")
	}
	if !strings.Contains(out, "Lines: 10") {
		t.Error("missing lines")
	}
	if !strings.Contains(out, "Words: 50") {
		t.Error("missing words")
	}
	if !strings.Contains(out, "Chars: 200") {
		t.Error("missing chars")
	}
	if !strings.Contains(out, "Bytes: 250") {
		t.Error("missing bytes")
	}
}
