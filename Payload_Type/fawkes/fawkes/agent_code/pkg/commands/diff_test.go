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

func TestDiffLinesDeleteOnly(t *testing.T) {
	// All lines removed: a has content, b is empty
	a := []string{"line1", "line2", "line3"}
	b := []string{}
	hunks := diffLines(a, b, 1)

	if len(hunks) == 0 {
		t.Fatal("expected at least one hunk for delete-only diff")
	}
	combined := strings.Join(hunks, "")
	if !strings.Contains(combined, "-line1") || !strings.Contains(combined, "-line3") {
		t.Errorf("expected all lines removed: %s", combined)
	}
}

func TestDiffLinesAddOnly(t *testing.T) {
	// All lines added: a is empty, b has content
	a := []string{}
	b := []string{"new1", "new2", "new3"}
	hunks := diffLines(a, b, 1)

	if len(hunks) == 0 {
		t.Fatal("expected at least one hunk for add-only diff")
	}
	combined := strings.Join(hunks, "")
	if !strings.Contains(combined, "+new1") || !strings.Contains(combined, "+new3") {
		t.Errorf("expected all lines added: %s", combined)
	}
}

func TestDiffLinesIdentical(t *testing.T) {
	a := []string{"same1", "same2", "same3"}
	b := []string{"same1", "same2", "same3"}
	hunks := diffLines(a, b, 3)

	if len(hunks) != 0 {
		t.Errorf("expected no hunks for identical input, got %d", len(hunks))
	}
}

func TestDiffLinesMultipleHunks(t *testing.T) {
	// Changes far apart should produce separate hunks
	a := make([]string, 20)
	b := make([]string, 20)
	for i := range a {
		a[i] = strings.Repeat("x", i+1) // unique content to avoid confusing LCS
		b[i] = a[i]
	}
	a[2] = "old_near_start"
	b[2] = "new_near_start"
	a[17] = "old_near_end"
	b[17] = "new_near_end"

	hunks := diffLines(a, b, 1)
	if len(hunks) < 2 {
		t.Errorf("expected 2+ hunks for widely-separated changes, got %d", len(hunks))
	}
}

func TestDiffRemovedLines(t *testing.T) {
	// File2 has fewer lines than File1
	dir := t.TempDir()
	f1 := filepath.Join(dir, "file1.txt")
	f2 := filepath.Join(dir, "file2.txt")
	os.WriteFile(f1, []byte("line1\nline2\nline3\nline4\n"), 0644)
	os.WriteFile(f2, []byte("line1\nline4\n"), 0644)

	params, _ := json.Marshal(diffArgs{File1: f1, File2: f2})
	cmd := &DiffCommand{}
	result := cmd.Execute(structs.Task{Params: string(params)})

	if result.Status != "success" {
		t.Fatalf("expected success: %s", result.Output)
	}
	if !strings.Contains(result.Output, "-line2") {
		t.Errorf("expected removed line2: %s", result.Output)
	}
}

func TestDiffLinesLargeFileTruncation(t *testing.T) {
	// diffLines truncates files > 10000 lines
	a := make([]string, 10500)
	b := make([]string, 10500)
	for i := range a {
		a[i] = "same"
		b[i] = "same"
	}
	// Change something in the first 10000 lines (will be included)
	a[5000] = "old_line"
	b[5000] = "new_line"
	// Change something beyond 10000 lines (will be truncated)
	a[10200] = "old_beyond"
	b[10200] = "new_beyond"

	hunks := diffLines(a, b, 1)
	combined := strings.Join(hunks, "")

	// Should find the change within first 10000 lines
	if !strings.Contains(combined, "-old_line") || !strings.Contains(combined, "+new_line") {
		t.Errorf("expected diff within 10k lines, got: %s", combined[:200])
	}
	// Should NOT find the change beyond 10000 lines
	if strings.Contains(combined, "beyond") {
		t.Errorf("expected truncation of lines > 10000, but found beyond-10k change")
	}
}

func TestReadLinesPermissionDenied(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "noperm.txt")
	os.WriteFile(tmp, []byte("data\n"), 0644)
	os.Chmod(tmp, 0000)
	defer os.Chmod(tmp, 0644)

	_, err := readLines(tmp)
	if err == nil {
		t.Error("expected error for permission-denied file")
	}
}
