package commands

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// makeHistoryHome creates a temp home dir with the given history files.
// Each entry is (filename, content). Returns the temp dir path.
func makeHistoryHome(t *testing.T, files map[string]string) string {
	t.Helper()
	home := t.TempDir()
	for name, content := range files {
		path := filepath.Join(home, name)
		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}
	return home
}

// TestHistoryClearNoFiles covers the `len(files) == 0` early-return in historyClear
// (line 216-221) — triggered when there are no history files found.
func TestHistoryClearNoFiles(t *testing.T) {
	home := t.TempDir() // empty — no history files
	t.Setenv("HOME", home)

	result := historyClear("", false)
	if result.Status != "success" {
		t.Fatalf("expected success, got %q: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "No history files found") {
		t.Errorf("expected 'No history files found', got: %s", result.Output)
	}
}

// TestHistoryClearSelectiveShellOnly covers the clearAll=false branch (lines 232-241)
// in historyClear — shell history files are cleared, app-specific ones are skipped.
func TestHistoryClearSelectiveShellOnly(t *testing.T) {
	home := makeHistoryHome(t, map[string]string{
		".bash_history":   "ls -la\npwd\n",
		".python_history": "import os\nprint('hello')\n",
	})
	t.Setenv("HOME", home)

	result := historyClear("", false)
	if result.Status != "success" {
		t.Fatalf("expected success, got %q: %s", result.Status, result.Output)
	}

	// bash_history should be cleared (shell type)
	if !strings.Contains(result.Output, "[OK]") {
		t.Errorf("expected at least one [OK] cleared file, got: %s", result.Output)
	}
	// python_history should be skipped (app type)
	if !strings.Contains(result.Output, "[SKIP]") {
		t.Errorf("expected at least one [SKIP] entry for python_history, got: %s", result.Output)
	}

	// Verify bash_history is now empty
	data, err := os.ReadFile(filepath.Join(home, ".bash_history"))
	if err != nil {
		t.Fatal(err)
	}
	if len(data) != 0 {
		t.Errorf("expected .bash_history to be empty after clear, got %d bytes", len(data))
	}
}

// TestHistoryClearAll covers the clearAll=true branch in historyClear — all history
// files including app-specific ones are cleared (no SKIP entries).
func TestHistoryClearAll(t *testing.T) {
	home := makeHistoryHome(t, map[string]string{
		".bash_history":   "ls -la\n",
		".python_history": "import sys\n",
	})
	t.Setenv("HOME", home)

	result := historyClear("", true)
	if result.Status != "success" {
		t.Fatalf("expected success, got %q: %s", result.Status, result.Output)
	}

	// No SKIP entries when clearAll=true
	if strings.Contains(result.Output, "[SKIP]") {
		t.Errorf("expected no [SKIP] entries with clearAll=true, got: %s", result.Output)
	}

	// Both files should be empty
	for _, name := range []string{".bash_history", ".python_history"} {
		data, err := os.ReadFile(filepath.Join(home, name))
		if err != nil {
			t.Fatal(err)
		}
		if len(data) != 0 {
			t.Errorf("expected %s to be empty after clear-all, got %d bytes", name, len(data))
		}
	}
}

// TestHistoryClearFailedTruncation covers the `os.Truncate error → failed++` branch
// (lines 244-246) in historyClear — triggered by a read-only history file.
func TestHistoryClearFailedTruncation(t *testing.T) {
	home := makeHistoryHome(t, map[string]string{
		".bash_history": "some history\n",
	})
	t.Setenv("HOME", home)

	// Make the file read-only so os.Truncate fails
	histPath := filepath.Join(home, ".bash_history")
	if err := os.Chmod(histPath, 0444); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(histPath, 0644) // restore for cleanup

	result := historyClear("", false)
	// Should be "error" because failed > 0 && cleared == 0
	if result.Status != "error" {
		t.Errorf("expected error when truncation fails, got %q: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "[FAIL]") {
		t.Errorf("expected [FAIL] entry in output, got: %s", result.Output)
	}
}
