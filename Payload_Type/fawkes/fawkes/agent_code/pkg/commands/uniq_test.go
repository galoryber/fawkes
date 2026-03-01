package commands

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestUniqBasic(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "data.txt")
	os.WriteFile(f, []byte("apple\napple\nbanana\nbanana\nbanana\ncherry\n"), 0644)

	params, _ := json.Marshal(uniqArgs{Path: f})
	cmd := &UniqCommand{}
	result := cmd.Execute(structs.Task{Params: string(params)})

	if result.Status != "success" {
		t.Fatalf("expected success, got %s: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "3 groups") {
		t.Fatalf("expected 3 groups, got: %s", result.Output)
	}
}

func TestUniqCount(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "data.txt")
	os.WriteFile(f, []byte("apple\napple\napple\nbanana\ncherry\ncherry\n"), 0644)

	params, _ := json.Marshal(uniqArgs{Path: f, Count: true})
	cmd := &UniqCommand{}
	result := cmd.Execute(structs.Task{Params: string(params)})

	if result.Status != "success" {
		t.Fatalf("expected success, got %s: %s", result.Status, result.Output)
	}
	// Count mode should show numbers — apple should be first (3 occurrences)
	if !strings.Contains(result.Output, "3 apple") && !strings.Contains(result.Output, "3  apple") {
		// Check for formatted count
		lines := strings.Split(result.Output, "\n")
		found := false
		for _, l := range lines {
			if strings.Contains(l, "apple") && strings.Contains(l, "3") {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("expected apple with count 3, got: %s", result.Output)
		}
	}
}

func TestUniqDuplicateOnly(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "data.txt")
	os.WriteFile(f, []byte("apple\napple\nbanana\ncherry\ncherry\n"), 0644)

	params, _ := json.Marshal(uniqArgs{Path: f, Duplicate: true})
	cmd := &UniqCommand{}
	result := cmd.Execute(structs.Task{Params: string(params)})

	if result.Status != "success" {
		t.Fatalf("expected success, got %s: %s", result.Status, result.Output)
	}
	// banana appears only once, should not be in output
	lines := strings.Split(result.Output, "\n")
	for _, l := range lines {
		if strings.TrimSpace(l) == "banana" {
			t.Fatalf("banana should not appear in duplicate-only mode")
		}
	}
}

func TestUniqUniqueOnly(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "data.txt")
	os.WriteFile(f, []byte("apple\napple\nbanana\ncherry\ncherry\n"), 0644)

	params, _ := json.Marshal(uniqArgs{Path: f, Unique: true})
	cmd := &UniqCommand{}
	result := cmd.Execute(structs.Task{Params: string(params)})

	if result.Status != "success" {
		t.Fatalf("expected success, got %s: %s", result.Status, result.Output)
	}
	// Only banana appears once
	if !strings.Contains(result.Output, "banana") {
		t.Fatalf("expected banana in unique-only output, got: %s", result.Output)
	}
}

func TestUniqNonexistent(t *testing.T) {
	params, _ := json.Marshal(uniqArgs{Path: "/nonexistent/file.txt"})
	cmd := &UniqCommand{}
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Fatalf("expected error, got %s", result.Status)
	}
}

func TestUniqNoParams(t *testing.T) {
	cmd := &UniqCommand{}
	result := cmd.Execute(structs.Task{Params: ""})
	if result.Status != "error" {
		t.Fatalf("expected error, got %s", result.Status)
	}
}

func TestUniqEmptyPath(t *testing.T) {
	params, _ := json.Marshal(uniqArgs{Path: ""})
	cmd := &UniqCommand{}
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Fatalf("expected error, got %s", result.Status)
	}
}

func TestUniqEmptyFile(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "empty.txt")
	os.WriteFile(f, []byte(""), 0644)

	params, _ := json.Marshal(uniqArgs{Path: f})
	cmd := &UniqCommand{}
	result := cmd.Execute(structs.Task{Params: string(params)})

	if result.Status != "success" {
		t.Fatalf("expected success, got %s: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "0 lines") {
		t.Fatalf("expected 0 lines, got: %s", result.Output)
	}
}
