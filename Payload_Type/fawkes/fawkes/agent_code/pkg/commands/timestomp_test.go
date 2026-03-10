package commands

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"fawkes/pkg/structs"
)

func TestTimestompName(t *testing.T) {
	cmd := &TimestompCommand{}
	if cmd.Name() != "timestomp" {
		t.Errorf("expected 'timestomp', got %q", cmd.Name())
	}
}

func TestTimestompDescription(t *testing.T) {
	cmd := &TimestompCommand{}
	if cmd.Description() == "" {
		t.Error("description should not be empty")
	}
}

func TestTimestompGetExistingFile(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "testfile.txt")
	os.WriteFile(path, []byte("hello"), 0644)

	cmd := &TimestompCommand{}
	params, _ := json.Marshal(TimestompParams{
		Action: "get",
		Target: path,
	})
	task := structs.NewTask("t", "timestomp", "")
	task.Params = string(params)
	result := cmd.Execute(task)

	if result.Status != "success" {
		t.Fatalf("expected success, got %q: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "Modified:") {
		t.Errorf("expected output to contain 'Modified:', got: %s", result.Output)
	}
	if !strings.Contains(result.Output, path) {
		t.Errorf("expected output to contain file path %q, got: %s", path, result.Output)
	}
}

func TestTimestompGetNonexistent(t *testing.T) {
	cmd := &TimestompCommand{}
	params, _ := json.Marshal(TimestompParams{
		Action: "get",
		Target: "/nonexistent/file/path/does/not/exist.txt",
	})
	task := structs.NewTask("t", "timestomp", "")
	task.Params = string(params)
	result := cmd.Execute(task)

	if result.Status != "error" {
		t.Errorf("expected error status for nonexistent file, got %q: %s", result.Status, result.Output)
	}
}

func TestTimestompSetTimestamp(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "testfile.txt")
	os.WriteFile(path, []byte("hello"), 0644)

	targetTime := "2020-06-15T10:30:00Z"

	cmd := &TimestompCommand{}
	params, _ := json.Marshal(TimestompParams{
		Action:    "set",
		Target:    path,
		Timestamp: targetTime,
	})
	task := structs.NewTask("t", "timestomp", "")
	task.Params = string(params)
	result := cmd.Execute(task)

	if result.Status != "success" {
		t.Fatalf("expected success, got %q: %s", result.Status, result.Output)
	}

	// Verify the modification time was actually changed
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("failed to stat file: %v", err)
	}
	expected, _ := time.Parse(time.RFC3339, targetTime)
	diff := math.Abs(float64(info.ModTime().Unix() - expected.Unix()))
	if diff > 1 {
		t.Errorf("modification time not set correctly: got %v, expected %v", info.ModTime(), expected)
	}
}

func TestTimestompSetBadTimestamp(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "testfile.txt")
	os.WriteFile(path, []byte("hello"), 0644)

	cmd := &TimestompCommand{}
	params, _ := json.Marshal(TimestompParams{
		Action:    "set",
		Target:    path,
		Timestamp: "not-a-valid-timestamp",
	})
	task := structs.NewTask("t", "timestomp", "")
	task.Params = string(params)
	result := cmd.Execute(task)

	if result.Status != "error" {
		t.Errorf("expected error status for invalid timestamp, got %q: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "Error parsing timestamp") {
		t.Errorf("expected error message about parsing timestamp, got: %s", result.Output)
	}
}

func TestTimestompCopyTimestamps(t *testing.T) {
	tmp := t.TempDir()
	sourcePath := filepath.Join(tmp, "source.txt")
	targetPath := filepath.Join(tmp, "target.txt")

	os.WriteFile(sourcePath, []byte("source"), 0644)
	os.WriteFile(targetPath, []byte("target"), 0644)

	// Set the source file to a known timestamp
	knownTime := time.Date(2019, 3, 15, 8, 0, 0, 0, time.UTC)
	os.Chtimes(sourcePath, knownTime, knownTime)

	cmd := &TimestompCommand{}
	params, _ := json.Marshal(TimestompParams{
		Action: "copy",
		Target: targetPath,
		Source: sourcePath,
	})
	task := structs.NewTask("t", "timestomp", "")
	task.Params = string(params)
	result := cmd.Execute(task)

	if result.Status != "success" {
		t.Fatalf("expected success, got %q: %s", result.Status, result.Output)
	}

	// Verify the target file's modification time matches the source
	targetInfo, err := os.Stat(targetPath)
	if err != nil {
		t.Fatalf("failed to stat target: %v", err)
	}
	diff := math.Abs(float64(targetInfo.ModTime().Unix() - knownTime.Unix()))
	if diff > 1 {
		t.Errorf("target mod time %v does not match source %v", targetInfo.ModTime(), knownTime)
	}
}

func TestTimestompCopyMissingSource(t *testing.T) {
	tmp := t.TempDir()
	targetPath := filepath.Join(tmp, "target.txt")
	os.WriteFile(targetPath, []byte("target"), 0644)

	cmd := &TimestompCommand{}
	params, _ := json.Marshal(TimestompParams{
		Action: "copy",
		Target: targetPath,
		Source: "", // Empty source
	})
	task := structs.NewTask("t", "timestomp", "")
	task.Params = string(params)
	result := cmd.Execute(task)

	if result.Status != "error" {
		t.Errorf("expected error status for missing source, got %q: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "source file path is required") {
		t.Errorf("expected error about source file, got: %s", result.Output)
	}
}

func TestTimestompPlainTextGet(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "test.txt")
	os.WriteFile(tmpFile, []byte("hello"), 0644)

	cmd := &TimestompCommand{}
	result := cmd.Execute(structs.Task{Params: "get " + tmpFile})
	if result.Status != "success" {
		t.Errorf("plain text 'get <file>' should succeed, got %s: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "Accessed:") {
		t.Errorf("expected timestamp output: %s", result.Output)
	}
}

func TestTimestompMatch(t *testing.T) {
	tmp := t.TempDir()
	// Create several sibling files with known timestamps spanning a range
	baseTime := time.Date(2023, 6, 1, 12, 0, 0, 0, time.UTC)
	for i := 0; i < 10; i++ {
		f := filepath.Join(tmp, strings.Replace("file_XX.txt", "XX", time.Duration(i).String(), 1))
		os.WriteFile(f, []byte("data"), 0644)
		fileTime := baseTime.Add(time.Duration(i) * 24 * time.Hour)
		os.Chtimes(f, fileTime, fileTime)
	}

	// Create the target with a very different timestamp
	target := filepath.Join(tmp, "payload.exe")
	os.WriteFile(target, []byte("payload"), 0644)
	os.Chtimes(target, time.Now(), time.Now())

	cmd := &TimestompCommand{}
	params, _ := json.Marshal(TimestompParams{
		Action: "match",
		Target: target,
	})
	task := structs.NewTask("t", "timestomp", "")
	task.Params = string(params)
	result := cmd.Execute(task)

	if result.Status != "success" {
		t.Fatalf("expected success, got %q: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "Matched timestamps") {
		t.Errorf("expected 'Matched timestamps' in output, got: %s", result.Output)
	}
	if !strings.Contains(result.Output, "10 sibling files") {
		t.Errorf("expected '10 sibling files' in output, got: %s", result.Output)
	}

	// Verify the target's timestamp is within the IQR of sibling files
	info, err := os.Stat(target)
	if err != nil {
		t.Fatalf("failed to stat target: %v", err)
	}
	mtime := info.ModTime()
	// IQR range: Q1 = day 2 (index 2), Q3 = day 7 (index 7)
	q1 := baseTime.Add(2 * 24 * time.Hour)
	q3 := baseTime.Add(7 * 24 * time.Hour)
	if mtime.Before(q1.Add(-time.Second)) || mtime.After(q3.Add(time.Second)) {
		t.Errorf("target mtime %v is outside IQR range [%v, %v]", mtime, q1, q3)
	}
}

func TestTimestompMatchTooFewFiles(t *testing.T) {
	tmp := t.TempDir()
	// Only one sibling file (need at least 2)
	os.WriteFile(filepath.Join(tmp, "only.txt"), []byte("data"), 0644)
	target := filepath.Join(tmp, "target.txt")
	os.WriteFile(target, []byte("data"), 0644)

	cmd := &TimestompCommand{}
	params, _ := json.Marshal(TimestompParams{
		Action: "match",
		Target: target,
	})
	task := structs.NewTask("t", "timestomp", "")
	task.Params = string(params)
	result := cmd.Execute(task)

	// Should fail — only 1 sibling (target itself excluded)
	if result.Status != "error" {
		t.Errorf("expected error with too few siblings, got %q: %s", result.Status, result.Output)
	}
}

func TestTimestompRandom(t *testing.T) {
	tmp := t.TempDir()
	target := filepath.Join(tmp, "target.txt")
	os.WriteFile(target, []byte("data"), 0644)

	rangeStart := "2020-01-01"
	rangeEnd := "2020-12-31"

	cmd := &TimestompCommand{}
	params, _ := json.Marshal(TimestompParams{
		Action:    "random",
		Target:    target,
		Source:    rangeStart,
		Timestamp: rangeEnd,
	})
	task := structs.NewTask("t", "timestomp", "")
	task.Params = string(params)
	result := cmd.Execute(task)

	if result.Status != "success" {
		t.Fatalf("expected success, got %q: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "random time") {
		t.Errorf("expected 'random time' in output, got: %s", result.Output)
	}

	// Verify timestamp is within the specified range
	info, err := os.Stat(target)
	if err != nil {
		t.Fatalf("failed to stat: %v", err)
	}
	mtime := info.ModTime()
	start := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	end := time.Date(2020, 12, 31, 0, 0, 0, 0, time.UTC)
	if mtime.Before(start.Add(-time.Second)) || mtime.After(end.Add(time.Second)) {
		t.Errorf("target mtime %v is outside range [%v, %v]", mtime, start, end)
	}
}

func TestTimestompRandomMissingRange(t *testing.T) {
	tmp := t.TempDir()
	target := filepath.Join(tmp, "target.txt")
	os.WriteFile(target, []byte("data"), 0644)

	cmd := &TimestompCommand{}
	params, _ := json.Marshal(TimestompParams{
		Action: "random",
		Target: target,
		Source: "2020-01-01",
		// Missing timestamp (range end)
	})
	task := structs.NewTask("t", "timestomp", "")
	task.Params = string(params)
	result := cmd.Execute(task)

	if result.Status != "error" {
		t.Errorf("expected error with missing range end, got %q: %s", result.Status, result.Output)
	}
}

func TestParseTimestamp(t *testing.T) {
	tests := []struct {
		input string
		year  int
		month time.Month
		day   int
	}{
		{"2024-01-15T10:30:00Z", 2024, 1, 15},
		{"2024-01-15T10:30:00", 2024, 1, 15},
		{"2024-01-15 10:30:00", 2024, 1, 15},
		{"2024-01-15", 2024, 1, 15},
		{"01/15/2024 10:30:00", 2024, 1, 15},
		{"01/15/2024", 2024, 1, 15},
	}
	for _, tt := range tests {
		parsed, err := parseTimestamp(tt.input)
		if err != nil {
			t.Errorf("parseTimestamp(%q) error: %v", tt.input, err)
			continue
		}
		if parsed.Year() != tt.year || parsed.Month() != tt.month || parsed.Day() != tt.day {
			t.Errorf("parseTimestamp(%q) = %v, want %d-%02d-%02d", tt.input, parsed, tt.year, tt.month, tt.day)
		}
	}
}

func TestParseTimestampInvalid(t *testing.T) {
	_, err := parseTimestamp("not-a-date")
	if err == nil {
		t.Error("expected error for invalid timestamp")
	}
}

func TestRandomTimeBetween(t *testing.T) {
	start := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	end := time.Date(2020, 12, 31, 0, 0, 0, 0, time.UTC)

	for i := 0; i < 20; i++ {
		result, err := randomTimeBetween(start, end)
		if err != nil {
			t.Fatalf("randomTimeBetween error: %v", err)
		}
		if result.Before(start) || result.After(end) {
			t.Errorf("result %v outside range [%v, %v]", result, start, end)
		}
	}
}

func TestRandomTimeBetween_Reversed(t *testing.T) {
	start := time.Date(2020, 12, 31, 0, 0, 0, 0, time.UTC)
	end := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)

	// Should swap start/end internally
	result, err := randomTimeBetween(start, end)
	if err != nil {
		t.Fatalf("randomTimeBetween error: %v", err)
	}
	if result.Before(end) || result.After(start) {
		t.Errorf("result %v outside swapped range [%v, %v]", result, end, start)
	}
}

func TestRandomTimeBetween_SameTime(t *testing.T) {
	same := time.Date(2020, 6, 15, 12, 0, 0, 0, time.UTC)
	result, err := randomTimeBetween(same, same)
	if err != nil {
		t.Fatalf("randomTimeBetween error: %v", err)
	}
	if !result.Equal(same) {
		t.Errorf("expected %v for same start/end, got %v", same, result)
	}
}
