package commands

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFormatSize(t *testing.T) {
	tests := []struct {
		bytes    int64
		expected string
	}{
		{0, "0 B"},
		{512, "512 B"},
		{1024, "1.0 KB"},
		{1536, "1.5 KB"},
		{1048576, "1.0 MB"},
		{1572864, "1.5 MB"},
		{1073741824, "1.0 GB"},
		{2684354560, "2.5 GB"},
	}
	for _, tt := range tests {
		result := formatSize(tt.bytes)
		if result != tt.expected {
			t.Errorf("formatSize(%d) = %q, want %q", tt.bytes, result, tt.expected)
		}
	}
}

func TestDeduplicatePSTFiles(t *testing.T) {
	files := []pstFileInfo{
		{Path: `C:\Users\admin\Documents\Outlook Files\archive.pst`, Source: "default path", Size: 1000},
		{Path: `C:\Users\admin\Documents\Outlook Files\archive.pst`, Source: "registry", Profile: "Outlook", Size: 1000},
		{Path: `C:\Users\admin\Documents\Outlook Files\work.pst`, Source: "default path", Size: 2000},
	}

	result := deduplicatePSTFiles(files)
	if len(result) != 2 {
		t.Fatalf("expected 2 unique files, got %d", len(result))
	}

	// Registry source should win (has Profile metadata)
	if result[0].Profile != "Outlook" {
		t.Errorf("expected registry source to take precedence, got source=%q profile=%q", result[0].Source, result[0].Profile)
	}
}

func TestDeduplicatePSTFiles_CaseInsensitive(t *testing.T) {
	files := []pstFileInfo{
		{Path: `C:\Users\Admin\file.pst`, Source: "default path"},
		{Path: `c:\users\admin\file.pst`, Source: "registry", Profile: "Default"},
	}

	result := deduplicatePSTFiles(files)
	if len(result) != 1 {
		t.Fatalf("expected 1 file after case-insensitive dedup, got %d", len(result))
	}
}

func TestDeduplicatePSTFiles_Empty(t *testing.T) {
	result := deduplicatePSTFiles(nil)
	if len(result) != 0 {
		t.Fatalf("expected 0 files, got %d", len(result))
	}
}

func TestFindPSTFiles(t *testing.T) {
	dir := t.TempDir()

	// Create test PST and OST files
	for _, name := range []string{"archive.pst", "main.ost", "notes.txt", "report.docx"} {
		os.WriteFile(filepath.Join(dir, name), []byte("test content"), 0644)
	}

	// Create a subdirectory (should not recurse)
	subDir := filepath.Join(dir, "subdir")
	os.Mkdir(subDir, 0755)
	os.WriteFile(filepath.Join(subDir, "nested.pst"), []byte("nested"), 0644)

	files := findPSTFiles(dir)
	if len(files) != 2 {
		t.Fatalf("expected 2 PST/OST files, got %d", len(files))
	}

	types := map[string]bool{}
	for _, f := range files {
		types[f.Type] = true
		if f.Size == 0 {
			t.Errorf("file %s has zero size", f.Path)
		}
	}
	if !types["PST"] {
		t.Error("expected to find a PST file")
	}
	if !types["OST"] {
		t.Error("expected to find an OST file")
	}
}

func TestFindPSTFiles_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	files := findPSTFiles(dir)
	if len(files) != 0 {
		t.Fatalf("expected 0 files in empty dir, got %d", len(files))
	}
}

func TestFindPSTFiles_NonexistentDir(t *testing.T) {
	files := findPSTFiles("/nonexistent/path/12345")
	if files != nil {
		t.Fatalf("expected nil for nonexistent dir, got %d files", len(files))
	}
}
