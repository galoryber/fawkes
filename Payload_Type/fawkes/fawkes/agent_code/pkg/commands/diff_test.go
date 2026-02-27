package commands

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestDiffIdenticalFiles(t *testing.T) {
	dir := t.TempDir()
	f1 := filepath.Join(dir, "file1.txt")
	f2 := filepath.Join(dir, "file2.txt")
	content := "line1\nline2\nline3\n"
	os.WriteFile(f1, []byte(content), 0644)
	os.WriteFile(f2, []byte(content), 0644)

	params, _ := json.Marshal(diffArgs{File1: f1, File2: f2})
	cmd := &DiffCommand{}
	result := cmd.Execute(structs.Task{Params: string(params)})

	if result.Status != "success" {
		t.Fatalf("expected success, got %s: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "identical") {
		t.Fatalf("expected identical message, got: %s", result.Output)
	}
}

func TestDiffDifferentFiles(t *testing.T) {
	dir := t.TempDir()
	f1 := filepath.Join(dir, "file1.txt")
	f2 := filepath.Join(dir, "file2.txt")
	os.WriteFile(f1, []byte("line1\nline2\nline3\n"), 0644)
	os.WriteFile(f2, []byte("line1\nmodified\nline3\n"), 0644)

	params, _ := json.Marshal(diffArgs{File1: f1, File2: f2})
	cmd := &DiffCommand{}
	result := cmd.Execute(structs.Task{Params: string(params)})

	if result.Status != "success" {
		t.Fatalf("expected success, got %s: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "-line2") {
		t.Fatalf("expected removed line2, got: %s", result.Output)
	}
	if !strings.Contains(result.Output, "+modified") {
		t.Fatalf("expected added modified, got: %s", result.Output)
	}
}

func TestDiffAddedLines(t *testing.T) {
	dir := t.TempDir()
	f1 := filepath.Join(dir, "file1.txt")
	f2 := filepath.Join(dir, "file2.txt")
	os.WriteFile(f1, []byte("line1\nline2\n"), 0644)
	os.WriteFile(f2, []byte("line1\nline2\nline3\nline4\n"), 0644)

	params, _ := json.Marshal(diffArgs{File1: f1, File2: f2})
	cmd := &DiffCommand{}
	result := cmd.Execute(structs.Task{Params: string(params)})

	if result.Status != "success" {
		t.Fatalf("expected success, got %s: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "+line3") {
		t.Fatalf("expected added line3, got: %s", result.Output)
	}
}

func TestDiffNonexistentFile(t *testing.T) {
	dir := t.TempDir()
	f1 := filepath.Join(dir, "exists.txt")
	f2 := filepath.Join(dir, "nope.txt")
	os.WriteFile(f1, []byte("data\n"), 0644)

	params, _ := json.Marshal(diffArgs{File1: f1, File2: f2})
	cmd := &DiffCommand{}
	result := cmd.Execute(structs.Task{Params: string(params)})

	if result.Status != "error" {
		t.Fatalf("expected error, got %s", result.Status)
	}
}

func TestDiffNoParams(t *testing.T) {
	cmd := &DiffCommand{}
	result := cmd.Execute(structs.Task{Params: ""})
	if result.Status != "error" {
		t.Fatalf("expected error, got %s", result.Status)
	}
}

func TestDiffEmptyPaths(t *testing.T) {
	params, _ := json.Marshal(diffArgs{File1: "", File2: ""})
	cmd := &DiffCommand{}
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Fatalf("expected error, got %s", result.Status)
	}
}

func TestDiffEmptyFiles(t *testing.T) {
	dir := t.TempDir()
	f1 := filepath.Join(dir, "empty1.txt")
	f2 := filepath.Join(dir, "empty2.txt")
	os.WriteFile(f1, []byte(""), 0644)
	os.WriteFile(f2, []byte(""), 0644)

	params, _ := json.Marshal(diffArgs{File1: f1, File2: f2})
	cmd := &DiffCommand{}
	result := cmd.Execute(structs.Task{Params: string(params)})

	if result.Status != "success" {
		t.Fatalf("expected success, got %s: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "identical") {
		t.Fatalf("expected identical, got: %s", result.Output)
	}
}

func TestDiffContext(t *testing.T) {
	dir := t.TempDir()
	f1 := filepath.Join(dir, "file1.txt")
	f2 := filepath.Join(dir, "file2.txt")
	os.WriteFile(f1, []byte("a\nb\nc\nd\ne\nf\ng\n"), 0644)
	os.WriteFile(f2, []byte("a\nb\nX\nd\ne\nf\ng\n"), 0644)

	params, _ := json.Marshal(diffArgs{File1: f1, File2: f2, Context: 1})
	cmd := &DiffCommand{}
	result := cmd.Execute(structs.Task{Params: string(params)})

	if result.Status != "success" {
		t.Fatalf("expected success, got %s: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "@@") {
		t.Fatalf("expected hunk header, got: %s", result.Output)
	}
}

func TestReadLines(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "test.txt")
	os.WriteFile(f, []byte("line1\nline2\nline3"), 0644)

	lines, err := readLines(f)
	if err != nil {
		t.Fatalf("readLines error: %v", err)
	}
	if len(lines) != 3 {
		t.Fatalf("expected 3 lines, got %d", len(lines))
	}
}

func TestDiffLinesFunc(t *testing.T) {
	a := []string{"line1", "line2", "line3"}
	b := []string{"line1", "modified", "line3"}
	hunks := diffLines(a, b, 3)

	if len(hunks) == 0 {
		t.Fatal("expected at least one hunk")
	}
	combined := strings.Join(hunks, "")
	if !strings.Contains(combined, "-line2") || !strings.Contains(combined, "+modified") {
		t.Fatalf("expected diff content, got: %s", combined)
	}
}
