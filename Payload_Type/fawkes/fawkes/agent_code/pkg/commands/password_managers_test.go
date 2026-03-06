package commands

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestPasswordManagersName(t *testing.T) {
	cmd := &PasswordManagersCommand{}
	if cmd.Name() != "password-managers" {
		t.Errorf("expected 'password-managers', got %q", cmd.Name())
	}
}

func TestPasswordManagersDescription(t *testing.T) {
	cmd := &PasswordManagersCommand{}
	if cmd.Description() == "" {
		t.Error("expected non-empty description")
	}
}

func TestPasswordManagersEmptyParams(t *testing.T) {
	cmd := &PasswordManagersCommand{}
	result := cmd.Execute(structs.Task{Params: ""})
	if result.Status != "success" {
		t.Errorf("expected success, got %q: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "Password Manager Discovery") {
		t.Error("output should contain header")
	}
}

func TestPasswordManagersWithDepth(t *testing.T) {
	cmd := &PasswordManagersCommand{}
	result := cmd.Execute(structs.Task{Params: `{"depth": 1}`})
	if result.Status != "success" {
		t.Errorf("expected success, got %q: %s", result.Status, result.Output)
	}
}

func TestFindKDBX(t *testing.T) {
	// Create temp dir with a .kdbx file
	tmpDir := t.TempDir()
	kdbxPath := filepath.Join(tmpDir, "test.kdbx")
	os.WriteFile(kdbxPath, []byte("fake kdbx"), 0644)

	// Also create a nested one
	nestedDir := filepath.Join(tmpDir, "subdir")
	os.MkdirAll(nestedDir, 0755)
	os.WriteFile(filepath.Join(nestedDir, "nested.kdbx"), []byte("nested"), 0644)

	var results []pmResult
	findKDBX(tmpDir, 4, &results)

	if len(results) != 2 {
		t.Fatalf("expected 2 kdbx files, got %d", len(results))
	}
	if results[0].Manager != "KeePass" {
		t.Errorf("expected 'KeePass', got %q", results[0].Manager)
	}
}

func TestFindKDBX_DepthLimit(t *testing.T) {
	// Create deeply nested .kdbx
	tmpDir := t.TempDir()
	deepDir := filepath.Join(tmpDir, "a", "b", "c", "d", "e")
	os.MkdirAll(deepDir, 0755)
	os.WriteFile(filepath.Join(deepDir, "deep.kdbx"), []byte("deep"), 0644)

	// With depth 2, should not find it (it's 5 levels deep)
	var results []pmResult
	findKDBX(tmpDir, 2, &results)

	if len(results) != 0 {
		t.Errorf("expected 0 results with depth limit 2, got %d", len(results))
	}

	// With depth 6, should find it
	findKDBX(tmpDir, 6, &results)
	if len(results) != 1 {
		t.Errorf("expected 1 result with depth limit 6, got %d", len(results))
	}
}

func TestFindKDBX_CaseInsensitive(t *testing.T) {
	tmpDir := t.TempDir()
	os.WriteFile(filepath.Join(tmpDir, "Test.KDBX"), []byte("upper"), 0644)

	var results []pmResult
	findKDBX(tmpDir, 1, &results)

	if len(results) != 1 {
		t.Errorf("expected 1 result for .KDBX, got %d", len(results))
	}
}
