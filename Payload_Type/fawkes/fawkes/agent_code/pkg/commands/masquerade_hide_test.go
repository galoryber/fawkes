package commands

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"fawkes/pkg/structs"
)

func TestMasqueradeHideUnhide(t *testing.T) {
	// Create temp file
	dir := t.TempDir()
	testFile := filepath.Join(dir, "visible_file.txt")
	if err := os.WriteFile(testFile, []byte("test content"), 0644); err != nil {
		t.Fatal(err)
	}

	cmd := &MasqueradeCommand{}

	// Hide the file
	params, _ := json.Marshal(masqueradeArgs{Source: testFile, Technique: "hide"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Fatalf("hide failed: %s", result.Output)
	}

	// Check that hidden file exists with dot-prefix
	hiddenPath := filepath.Join(dir, ".visible_file.txt")
	if _, err := os.Stat(hiddenPath); err != nil {
		t.Fatalf("hidden file not found at %s: %v", hiddenPath, err)
	}

	// Original should not exist
	if _, err := os.Stat(testFile); err == nil {
		t.Error("original file still exists after hide")
	}

	// Unhide the file
	params, _ = json.Marshal(masqueradeArgs{Source: hiddenPath, Technique: "unhide"})
	result = cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Fatalf("unhide failed: %s", result.Output)
	}

	// Original name should be restored
	if _, err := os.Stat(testFile); err != nil {
		t.Fatalf("unhidden file not found at %s: %v", testFile, err)
	}
}

func TestMasqueradeHideAlreadyHidden(t *testing.T) {
	dir := t.TempDir()
	testFile := filepath.Join(dir, ".already_hidden")
	if err := os.WriteFile(testFile, []byte("test"), 0644); err != nil {
		t.Fatal(err)
	}

	cmd := &MasqueradeCommand{}
	params, _ := json.Marshal(masqueradeArgs{Source: testFile, Technique: "hide"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Fatalf("hide already-hidden failed: %s", result.Output)
	}
	// Should still exist at same path (no rename needed)
	if _, err := os.Stat(testFile); err != nil {
		t.Fatalf("already-hidden file missing: %v", err)
	}
}

func TestMasqueradeHideNonExistent(t *testing.T) {
	cmd := &MasqueradeCommand{}
	params, _ := json.Marshal(masqueradeArgs{Source: "/nonexistent/path", Technique: "hide"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Error("expected error for non-existent path")
	}
}

func TestMasqueradeUnhideNonExistent(t *testing.T) {
	cmd := &MasqueradeCommand{}
	params, _ := json.Marshal(masqueradeArgs{Source: "/nonexistent/path", Technique: "unhide"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Error("expected error for non-existent path")
	}
}

func TestMasqueradeHideDirectory(t *testing.T) {
	dir := t.TempDir()
	testDir := filepath.Join(dir, "visible_dir")
	if err := os.Mkdir(testDir, 0755); err != nil {
		t.Fatal(err)
	}

	cmd := &MasqueradeCommand{}
	params, _ := json.Marshal(masqueradeArgs{Source: testDir, Technique: "hide"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Fatalf("hide directory failed: %s", result.Output)
	}

	hiddenPath := filepath.Join(dir, ".visible_dir")
	if _, err := os.Stat(hiddenPath); err != nil {
		t.Fatalf("hidden directory not found: %v", err)
	}
}
