package commands

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestSortBasic(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "data.txt")
	os.WriteFile(f, []byte("cherry\napple\nbanana\n"), 0644)

	params, _ := json.Marshal(sortArgs{Path: f})
	cmd := &SortCommand{}
	result := cmd.Execute(structs.Task{Params: string(params)})

	if result.Status != "success" {
		t.Fatalf("expected success, got %s: %s", result.Status, result.Output)
	}
	lines := strings.Split(strings.TrimSpace(result.Output), "\n")
	// Skip header line
	dataLines := []string{}
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "[") {
			continue
		}
		dataLines = append(dataLines, l)
	}
	if len(dataLines) < 3 {
		t.Fatalf("expected 3 data lines, got %d: %v", len(dataLines), dataLines)
	}
	if dataLines[0] != "apple" {
		t.Fatalf("expected first line apple, got: %s", dataLines[0])
	}
}

func TestSortReverse(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "data.txt")
	os.WriteFile(f, []byte("apple\nbanana\ncherry\n"), 0644)

	params, _ := json.Marshal(sortArgs{Path: f, Reverse: true})
	cmd := &SortCommand{}
	result := cmd.Execute(structs.Task{Params: string(params)})

	if result.Status != "success" {
		t.Fatalf("expected success, got %s: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "(reversed)") {
		t.Fatalf("expected reversed indicator, got: %s", result.Output)
	}
}

func TestSortNumeric(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "data.txt")
	os.WriteFile(f, []byte("100 items\n20 items\n3 items\n"), 0644)

	params, _ := json.Marshal(sortArgs{Path: f, Numeric: true})
	cmd := &SortCommand{}
	result := cmd.Execute(structs.Task{Params: string(params)})

	if result.Status != "success" {
		t.Fatalf("expected success, got %s: %s", result.Status, result.Output)
	}
	lines := strings.Split(strings.TrimSpace(result.Output), "\n")
	dataLines := []string{}
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "[") {
			continue
		}
		dataLines = append(dataLines, l)
	}
	if len(dataLines) >= 1 && !strings.HasPrefix(dataLines[0], "3") {
		t.Fatalf("expected numeric sort (3 first), got: %v", dataLines)
	}
}

func TestSortUnique(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "data.txt")
	os.WriteFile(f, []byte("apple\nbanana\napple\ncherry\nbanana\n"), 0644)

	params, _ := json.Marshal(sortArgs{Path: f, Unique: true})
	cmd := &SortCommand{}
	result := cmd.Execute(structs.Task{Params: string(params)})

	if result.Status != "success" {
		t.Fatalf("expected success, got %s: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "(unique)") {
		t.Fatalf("expected unique indicator, got: %s", result.Output)
	}
	if strings.Count(result.Output, "apple") != 1 {
		t.Fatalf("expected apple once, got: %s", result.Output)
	}
}

func TestSortNonexistent(t *testing.T) {
	params, _ := json.Marshal(sortArgs{Path: "/nonexistent/file.txt"})
	cmd := &SortCommand{}
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Fatalf("expected error, got %s", result.Status)
	}
}

func TestSortNoParams(t *testing.T) {
	cmd := &SortCommand{}
	result := cmd.Execute(structs.Task{Params: ""})
	if result.Status != "error" {
		t.Fatalf("expected error, got %s", result.Status)
	}
}

func TestSortEmptyPath(t *testing.T) {
	params, _ := json.Marshal(sortArgs{Path: ""})
	cmd := &SortCommand{}
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Fatalf("expected error, got %s", result.Status)
	}
}

func TestExtractNumber(t *testing.T) {
	tests := []struct {
		input    string
		expected float64
	}{
		{"100 items", 100},
		{"3.14 pi", 3.14},
		{"-5 degrees", -5},
		{"no number", 0},
		{"", 0},
	}
	for _, tc := range tests {
		got := extractNumber(tc.input)
		if got != tc.expected {
			t.Errorf("extractNumber(%q) = %f, want %f", tc.input, got, tc.expected)
		}
	}
}

func TestUniqueLinesFunc(t *testing.T) {
	lines := []string{"a", "a", "b", "b", "b", "c"}
	result := uniqueLines(lines)
	if len(result) != 3 {
		t.Fatalf("expected 3 unique lines, got %d: %v", len(result), result)
	}
}
