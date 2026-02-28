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
