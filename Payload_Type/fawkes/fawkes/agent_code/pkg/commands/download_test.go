package commands

import (
	"archive/zip"
	"fawkes/pkg/structs"
	"os"
	"path/filepath"
	"testing"
)

func TestDownloadName(t *testing.T) {
	cmd := &DownloadCommand{}
	if cmd.Name() != "download" {
		t.Errorf("expected 'download', got '%s'", cmd.Name())
	}
}

func TestDownloadDescription(t *testing.T) {
	cmd := &DownloadCommand{}
	if cmd.Description() == "" {
		t.Error("description should not be empty")
	}
}

func TestDownloadEmptyPath(t *testing.T) {
	cmd := &DownloadCommand{}
	result := cmd.Execute(structs.Task{Params: ""})
	if result.Status != "error" {
		t.Errorf("expected error for empty path, got '%s'", result.Status)
	}
	if !result.Completed {
		t.Error("should be completed on error")
	}
}

func TestDownloadNonexistentFile(t *testing.T) {
	cmd := &DownloadCommand{}
	result := cmd.Execute(structs.Task{Params: "/nonexistent/path/file.txt"})
	if result.Status != "error" {
		t.Errorf("expected error for nonexistent file, got '%s'", result.Status)
	}
}

func TestDownloadQuotedPath(t *testing.T) {
	cmd := &DownloadCommand{}
	// Path with quotes should still fail gracefully for nonexistent file
	result := cmd.Execute(structs.Task{Params: `"/nonexistent/path/file.txt"`})
	if result.Status != "error" {
		t.Errorf("expected error for nonexistent quoted path, got '%s'", result.Status)
	}
}

func TestZipDirectoryBasic(t *testing.T) {
	// Create test directory structure
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "file1.txt"), []byte("hello"), 0644)
	os.WriteFile(filepath.Join(dir, "file2.txt"), []byte("world"), 0644)

	tmpFile, err := os.CreateTemp("", "test-zip-*.zip")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	count, totalSize, zipErr := zipDirectory(tmpFile, dir)
	tmpFile.Close()

	if zipErr != nil {
		t.Fatalf("unexpected error: %v", zipErr)
	}
	if count != 2 {
		t.Errorf("expected 2 files, got %d", count)
	}
	if totalSize != 10 { // "hello" + "world"
		t.Errorf("expected total size 10, got %d", totalSize)
	}

	// Verify zip is valid
	r, err := zip.OpenReader(tmpFile.Name())
	if err != nil {
		t.Fatalf("zip not valid: %v", err)
	}
	defer r.Close()
	if len(r.File) != 2 {
		t.Errorf("expected 2 entries in zip, got %d", len(r.File))
	}
}

func TestZipDirectoryNested(t *testing.T) {
	dir := t.TempDir()
	subDir := filepath.Join(dir, "sub")
	os.MkdirAll(subDir, 0755)
	os.WriteFile(filepath.Join(dir, "root.txt"), []byte("root"), 0644)
	os.WriteFile(filepath.Join(subDir, "nested.txt"), []byte("nested"), 0644)

	tmpFile, err := os.CreateTemp("", "test-zip-*.zip")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	count, _, zipErr := zipDirectory(tmpFile, dir)
	tmpFile.Close()

	if zipErr != nil {
		t.Fatalf("unexpected error: %v", zipErr)
	}
	if count != 2 {
		t.Errorf("expected 2 files, got %d", count)
	}

	// Verify paths in zip
	r, err := zip.OpenReader(tmpFile.Name())
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	names := make(map[string]bool)
	for _, f := range r.File {
		names[f.Name] = true
	}
	if !names["root.txt"] {
		t.Error("missing root.txt in zip")
	}
	if !names["sub/nested.txt"] {
		t.Error("missing sub/nested.txt in zip")
	}
}

func TestZipDirectoryEmpty(t *testing.T) {
	dir := t.TempDir()

	tmpFile, err := os.CreateTemp("", "test-zip-*.zip")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	count, totalSize, zipErr := zipDirectory(tmpFile, dir)
	tmpFile.Close()

	if zipErr != nil {
		t.Fatalf("unexpected error: %v", zipErr)
	}
	if count != 0 {
		t.Errorf("expected 0 files, got %d", count)
	}
	if totalSize != 0 {
		t.Errorf("expected 0 total size, got %d", totalSize)
	}
}

func TestZipDirectoryDepthLimit(t *testing.T) {
	// Create deeply nested structure (12 levels, maxDepth is 10)
	dir := t.TempDir()
	current := dir
	for i := 0; i < 12; i++ {
		current = filepath.Join(current, "d")
		os.MkdirAll(current, 0755)
		os.WriteFile(filepath.Join(current, "file.txt"), []byte("x"), 0644)
	}

	tmpFile, err := os.CreateTemp("", "test-zip-*.zip")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	count, _, zipErr := zipDirectory(tmpFile, dir)
	tmpFile.Close()

	if zipErr != nil {
		t.Fatalf("unexpected error: %v", zipErr)
	}
	if count > 10 {
		t.Errorf("depth limit not enforced: got %d files (expected <= 10)", count)
	}
}

func TestZipDirectorySkipsInaccessible(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "ok.txt"), []byte("ok"), 0644)

	// Create unreadable file
	unreadable := filepath.Join(dir, "nope.txt")
	os.WriteFile(unreadable, []byte("secret"), 0000)
	defer os.Chmod(unreadable, 0644) // restore for cleanup

	tmpFile, err := os.CreateTemp("", "test-zip-*.zip")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	count, _, zipErr := zipDirectory(tmpFile, dir)
	tmpFile.Close()

	if zipErr != nil {
		t.Fatalf("unexpected error: %v", zipErr)
	}
	// Should get at least 1 (ok.txt) — nope.txt may or may not be accessible depending on user
	if count < 1 {
		t.Errorf("expected at least 1 file, got %d", count)
	}
}

func TestDownloadDirectoryEmptyDir(t *testing.T) {
	// downloadDirectory should return error for empty directory
	dir := t.TempDir()
	task := structs.Task{Params: dir}
	cmd := &DownloadCommand{}
	result := cmd.Execute(task)
	// Empty dir → error because no files to zip
	if result.Status != "error" {
		t.Errorf("expected error for empty directory, got '%s': %s", result.Status, result.Output)
	}
}

func TestZipDirectoryForwardSlashPaths(t *testing.T) {
	// Verify zip entries use forward slashes (zip standard)
	dir := t.TempDir()
	sub := filepath.Join(dir, "a", "b")
	os.MkdirAll(sub, 0755)
	os.WriteFile(filepath.Join(sub, "c.txt"), []byte("x"), 0644)

	tmpFile, err := os.CreateTemp("", "test-zip-*.zip")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	_, _, zipErr := zipDirectory(tmpFile, dir)
	tmpFile.Close()

	if zipErr != nil {
		t.Fatal(zipErr)
	}

	r, err := zip.OpenReader(tmpFile.Name())
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	for _, f := range r.File {
		if filepath.Separator != '/' && filepath.Base(f.Name) != f.Name {
			// On Windows, verify no backslashes
			if f.Name != "a/b/c.txt" {
				t.Errorf("expected forward slashes in zip path, got %s", f.Name)
			}
		}
	}
}
