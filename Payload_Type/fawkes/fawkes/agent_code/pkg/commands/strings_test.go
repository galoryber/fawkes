package commands

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestStringsBasic(t *testing.T) {
	// Create a file with mixed binary and text content
	tmp := filepath.Join(t.TempDir(), "test.bin")
	data := []byte{0x00, 0x00, 0x00}
	data = append(data, []byte("Hello World")...)
	data = append(data, []byte{0x00, 0xFF, 0xFE}...)
	data = append(data, []byte("second string here")...)
	data = append(data, []byte{0x00}...)
	os.WriteFile(tmp, data, 0644)

	cmd := &StringsCommand{}
	params, _ := json.Marshal(stringsArgs{Path: tmp})
	result := cmd.Execute(structs.Task{Params: string(params)})

	if result.Status != "success" {
		t.Fatalf("expected success, got %s: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "Hello World") {
		t.Errorf("expected 'Hello World' in output:\n%s", result.Output)
	}
	if !strings.Contains(result.Output, "second string here") {
		t.Errorf("expected 'second string here' in output:\n%s", result.Output)
	}
	if !strings.Contains(result.Output, "Found 2 strings") {
		t.Errorf("expected 2 strings found:\n%s", result.Output)
	}
}

func TestStringsMinLength(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "test.bin")
	data := []byte{0x00}
	data = append(data, []byte("ab")...) // too short for default min=4
	data = append(data, []byte{0x00}...)
	data = append(data, []byte("abcdef")...) // long enough
	data = append(data, []byte{0x00}...)
	os.WriteFile(tmp, data, 0644)

	cmd := &StringsCommand{}

	// Default min=4: should only find "abcdef"
	params, _ := json.Marshal(stringsArgs{Path: tmp})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if !strings.Contains(result.Output, "Found 1 strings") {
		t.Errorf("default min=4 should find 1 string:\n%s", result.Output)
	}

	// min=2: should find both
	params, _ = json.Marshal(stringsArgs{Path: tmp, MinLen: 2})
	result = cmd.Execute(structs.Task{Params: string(params)})
	if !strings.Contains(result.Output, "Found 2 strings") {
		t.Errorf("min=2 should find 2 strings:\n%s", result.Output)
	}
}

func TestStringsPattern(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "test.bin")
	data := []byte{0x00}
	data = append(data, []byte("http://example.com")...)
	data = append(data, []byte{0x00}...)
	data = append(data, []byte("plain text")...)
	data = append(data, []byte{0x00}...)
	data = append(data, []byte("HTTPS://secure.com")...)
	data = append(data, []byte{0x00}...)
	os.WriteFile(tmp, data, 0644)

	cmd := &StringsCommand{}
	params, _ := json.Marshal(stringsArgs{Path: tmp, Pattern: "http"})
	result := cmd.Execute(structs.Task{Params: string(params)})

	if result.Status != "success" {
		t.Fatalf("expected success: %s", result.Output)
	}
	// Case-insensitive: should find both http and HTTPS
	if !strings.Contains(result.Output, "http://example.com") {
		t.Error("should find http URL")
	}
	if !strings.Contains(result.Output, "HTTPS://secure.com") {
		t.Error("should find HTTPS URL (case-insensitive)")
	}
	if strings.Contains(result.Output, "plain text") {
		t.Error("should NOT include 'plain text' with http filter")
	}
}

func TestStringsOffset(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "test.bin")
	data := []byte("early string")
	data = append(data, make([]byte, 100)...)
	data = append(data, []byte("later string")...)
	data = append(data, []byte{0x00}...)
	os.WriteFile(tmp, data, 0644)

	cmd := &StringsCommand{}
	// Offset past "early string"
	params, _ := json.Marshal(stringsArgs{Path: tmp, Offset: 50})
	result := cmd.Execute(structs.Task{Params: string(params)})

	if strings.Contains(result.Output, "early string") {
		t.Error("should not find 'early string' with offset 50")
	}
	if !strings.Contains(result.Output, "later string") {
		t.Errorf("should find 'later string':\n%s", result.Output)
	}
}

func TestStringsOffsetExceedsSize(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "small.bin")
	os.WriteFile(tmp, []byte("hello"), 0644)

	cmd := &StringsCommand{}
	params, _ := json.Marshal(stringsArgs{Path: tmp, Offset: 1000})
	result := cmd.Execute(structs.Task{Params: string(params)})

	if result.Status != "error" {
		t.Errorf("expected error for offset exceeding file size, got %s", result.Status)
	}
}

func TestStringsNonexistentFile(t *testing.T) {
	cmd := &StringsCommand{}
	params, _ := json.Marshal(stringsArgs{Path: "/tmp/nonexistent_strings_test"})
	result := cmd.Execute(structs.Task{Params: string(params)})

	if result.Status != "error" {
		t.Errorf("expected error, got %s", result.Status)
	}
}

func TestStringsEmptyFile(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "empty.bin")
	os.WriteFile(tmp, []byte{}, 0644)

	cmd := &StringsCommand{}
	params, _ := json.Marshal(stringsArgs{Path: tmp})
	result := cmd.Execute(structs.Task{Params: string(params)})

	if result.Status != "success" {
		t.Fatalf("expected success: %s", result.Output)
	}
	if !strings.Contains(result.Output, "Found 0 strings") {
		t.Errorf("expected 0 strings in empty file:\n%s", result.Output)
	}
}

func TestStringsPureText(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "text.txt")
	os.WriteFile(tmp, []byte("line one\nline two\nline three\n"), 0644)

	cmd := &StringsCommand{}
	params, _ := json.Marshal(stringsArgs{Path: tmp})
	result := cmd.Execute(structs.Task{Params: string(params)})

	if result.Status != "success" {
		t.Fatalf("expected success: %s", result.Output)
	}
	// Newlines (0x0a) split strings, so "line one", "line two", "line three" should be found
	if !strings.Contains(result.Output, "line one") {
		t.Error("should find 'line one'")
	}
	if !strings.Contains(result.Output, "line three") {
		t.Error("should find 'line three'")
	}
}

func TestStringsNoParams(t *testing.T) {
	cmd := &StringsCommand{}
	result := cmd.Execute(structs.Task{Params: ""})
	if result.Status != "error" {
		t.Errorf("expected error with no params")
	}
}

func TestStringsEmptyPath(t *testing.T) {
	cmd := &StringsCommand{}
	params, _ := json.Marshal(stringsArgs{Path: ""})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error with empty path")
	}
}

func TestStringsMaxSize(t *testing.T) {
	// Create a file larger than our small max_size
	tmp := filepath.Join(t.TempDir(), "big.bin")
	data := make([]byte, 200)
	copy(data[0:], []byte("early text"))
	data[10] = 0x00
	copy(data[150:], []byte("late text"))
	data[159] = 0x00
	os.WriteFile(tmp, data, 0644)

	cmd := &StringsCommand{}
	// Limit scan to first 100 bytes — should only find "early text"
	params, _ := json.Marshal(stringsArgs{Path: tmp, MaxSize: 100})
	result := cmd.Execute(structs.Task{Params: string(params)})

	if !strings.Contains(result.Output, "early text") {
		t.Error("should find 'early text' within max_size")
	}
	if strings.Contains(result.Output, "late text") {
		t.Error("should NOT find 'late text' beyond max_size")
	}
}

func TestExtractStringsFunction(t *testing.T) {
	// Direct test of extractStrings
	data := "\x00hello\x00world\x00hi\x00"
	r := strings.NewReader(data)
	result := extractStrings(r, 4, "")

	if len(result) != 2 {
		t.Fatalf("expected 2 strings (min=4), got %d: %v", len(result), result)
	}
	if result[0] != "hello" || result[1] != "world" {
		t.Errorf("unexpected strings: %v", result)
	}
}
