package commands

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"fawkes/pkg/structs"
)

func TestCorruptFileRequiresConfirm(t *testing.T) {
	// Without confirm parameter, should fail
	result := corruptFile(encryptArgs{
		Path:    "/tmp/test.txt",
		Confirm: "",
	})
	if result.Status != "error" {
		t.Error("Expected error without confirm parameter")
	}

	// With wrong confirm value
	result = corruptFile(encryptArgs{
		Path:    "/tmp/test.txt",
		Confirm: "YES",
	})
	if result.Status != "error" {
		t.Error("Expected error with wrong confirm value")
	}
}

func TestCorruptFileActualCorruption(t *testing.T) {
	// Create a temp file with known content
	tmp := filepath.Join(t.TempDir(), "testfile.dat")
	original := make([]byte, 8192)
	for i := range original {
		original[i] = 0xAA
	}
	if err := os.WriteFile(tmp, original, 0644); err != nil {
		t.Fatal(err)
	}

	// Corrupt it
	result := corruptFile(encryptArgs{
		Path:    tmp,
		Confirm: "CORRUPT",
	})
	if result.Status != "success" {
		t.Fatalf("Expected success, got error: %s", result.Output)
	}

	// Verify first bytes are changed
	data, err := os.ReadFile(tmp)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) != len(original) {
		t.Errorf("File size changed: %d -> %d", len(original), len(data))
	}

	// First 4KB should be corrupted (different from 0xAA)
	allSame := true
	for i := 0; i < 4096 && i < len(data); i++ {
		if data[i] != 0xAA {
			allSame = false
			break
		}
	}
	if allSame {
		t.Error("First 4KB should be corrupted (not all 0xAA)")
	}

	// Parse result JSON
	var cr corruptResult
	if err := json.Unmarshal([]byte(result.Output), &cr); err != nil {
		t.Fatalf("Failed to parse result: %v", err)
	}
	if cr.BytesCorrupt <= 0 {
		t.Error("Expected bytes_corrupted > 0")
	}
	if cr.Method != "random-overwrite-head" {
		t.Errorf("Method = %q, expected 'random-overwrite-head'", cr.Method)
	}
}

func TestCorruptFileDirectory(t *testing.T) {
	result := corruptFile(encryptArgs{
		Path:    t.TempDir(),
		Confirm: "CORRUPT",
	})
	if result.Status != "error" {
		t.Error("Expected error for directory input")
	}
}

func TestCorruptFilesRequiresConfirm(t *testing.T) {
	result := corruptFiles(encryptArgs{
		Path:    "/tmp/*.txt",
		Confirm: "",
	})
	if result.Status != "error" {
		t.Error("Expected error without confirm parameter")
	}
}

func TestCorruptFilesBatchMode(t *testing.T) {
	dir := t.TempDir()

	// Create 3 test files
	for i := 0; i < 3; i++ {
		path := filepath.Join(dir, "file"+string(rune('a'+i))+".dat")
		data := make([]byte, 1024)
		for j := range data {
			data[j] = byte(i + 1)
		}
		if err := os.WriteFile(path, data, 0644); err != nil {
			t.Fatal(err)
		}
	}

	// Corrupt all .dat files
	result := corruptFiles(encryptArgs{
		Path:    filepath.Join(dir, "*.dat"),
		Confirm: "CORRUPT",
	})
	if result.Status != "success" {
		t.Fatalf("Expected success: %s", result.Output)
	}

	// Verify all files were corrupted
	matches, _ := filepath.Glob(filepath.Join(dir, "*.dat"))
	for _, m := range matches {
		data, err := os.ReadFile(m)
		if err != nil {
			t.Fatal(err)
		}
		if len(data) != 1024 {
			t.Errorf("File %s size changed", m)
		}
	}
}

// Helper to create a CommandResult for testing
func makeTaskParams(args interface{}) structs.Task {
	params, _ := json.Marshal(args)
	return structs.Task{Params: string(params)}
}
