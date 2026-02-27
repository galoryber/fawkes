package commands

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"fawkes/pkg/structs"
)

func TestTouchName(t *testing.T) {
	c := &TouchCommand{}
	if c.Name() != "touch" {
		t.Errorf("expected 'touch', got '%s'", c.Name())
	}
}

func TestTouchDescription(t *testing.T) {
	c := &TouchCommand{}
	if c.Description() == "" {
		t.Error("description should not be empty")
	}
}

func TestTouchEmptyParams(t *testing.T) {
	c := &TouchCommand{}
	result := c.Execute(structs.Task{Params: ""})
	if result.Status != "error" {
		t.Errorf("expected error, got %s", result.Status)
	}
}

func TestTouchBadJSON(t *testing.T) {
	c := &TouchCommand{}
	result := c.Execute(structs.Task{Params: "not json"})
	if result.Status != "error" {
		t.Errorf("expected error, got %s", result.Status)
	}
}

func TestTouchMissingPath(t *testing.T) {
	c := &TouchCommand{}
	params, _ := json.Marshal(touchArgs{})
	result := c.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error, got %s", result.Status)
	}
}

func TestTouchCreateNewFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "new_file.txt")

	c := &TouchCommand{}
	params, _ := json.Marshal(touchArgs{Path: path})
	result := c.Execute(structs.Task{Params: string(params)})

	if result.Status != "success" {
		t.Fatalf("expected success, got %s: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "Created") {
		t.Error("should say 'Created'")
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal("file should exist")
	}
	if info.Size() != 0 {
		t.Error("file should be empty")
	}
}

func TestTouchUpdateTimestamp(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "existing.txt")
	os.WriteFile(path, []byte("content"), 0644)

	// Set old timestamp
	oldTime := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	os.Chtimes(path, oldTime, oldTime)

	before, _ := os.Stat(path)
	if before.ModTime().After(time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC)) {
		t.Skip("could not set old timestamp")
	}

	c := &TouchCommand{}
	params, _ := json.Marshal(touchArgs{Path: path})
	result := c.Execute(structs.Task{Params: string(params)})

	if result.Status != "success" {
		t.Fatalf("expected success, got %s: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "Updated timestamps") {
		t.Error("should say 'Updated timestamps'")
	}

	after, _ := os.Stat(path)
	if !after.ModTime().After(before.ModTime()) {
		t.Error("modification time should be updated")
	}

	// Content should be preserved
	data, _ := os.ReadFile(path)
	if string(data) != "content" {
		t.Error("file content should be preserved")
	}
}

func TestTouchMkDir(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "a", "b", "c", "file.txt")

	c := &TouchCommand{}
	params, _ := json.Marshal(touchArgs{Path: path, MkDir: true})
	result := c.Execute(structs.Task{Params: string(params)})

	if result.Status != "success" {
		t.Fatalf("expected success, got %s: %s", result.Status, result.Output)
	}

	if _, err := os.Stat(path); err != nil {
		t.Fatal("file should exist in nested dirs")
	}
}

func TestTouchNoMkDirFails(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nonexistent", "file.txt")

	c := &TouchCommand{}
	params, _ := json.Marshal(touchArgs{Path: path})
	result := c.Execute(structs.Task{Params: string(params)})

	if result.Status != "error" {
		t.Errorf("expected error without mkdir, got %s", result.Status)
	}
}
