package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestFileTypeNoParams(t *testing.T) {
	cmd := &FileTypeCommand{}
	result := cmd.Execute(structs.Task{Params: ""})

	if result.Status != "error" {
		t.Fatalf("expected error, got %s: %s", result.Status, result.Output)
	}
}

func TestFileTypeEmptyPath(t *testing.T) {
	params, _ := json.Marshal(fileTypeArgs{})
	cmd := &FileTypeCommand{}
	result := cmd.Execute(structs.Task{Params: string(params)})

	if result.Status != "error" {
		t.Fatalf("expected error for empty path, got %s: %s", result.Status, result.Output)
	}
}

func TestFileTypeNonexistentFile(t *testing.T) {
	params, _ := json.Marshal(fileTypeArgs{Path: "/tmp/nonexistent_filetype_test_xyzzy"})
	cmd := &FileTypeCommand{}
	result := cmd.Execute(structs.Task{Params: string(params)})

	if result.Status != "error" {
		t.Fatalf("expected error for nonexistent file, got %s: %s", result.Status, result.Output)
	}
}

func TestFileTypeSingleText(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "test.txt")
	if err := os.WriteFile(tmpFile, []byte("Hello, world! This is a test file.\n"), 0644); err != nil {
		t.Fatal(err)
	}

	params, _ := json.Marshal(fileTypeArgs{Path: tmpFile})
	cmd := &FileTypeCommand{}
	result := cmd.Execute(structs.Task{Params: string(params)})

	if result.Status != "completed" {
		t.Fatalf("expected completed, got %s: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "Text/ASCII") {
		t.Fatalf("expected Text/ASCII, got: %s", result.Output)
	}
}

func TestFileTypePEMagic(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "test.exe")
	// MZ header
	data := []byte{0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00}
	if err := os.WriteFile(tmpFile, data, 0644); err != nil {
		t.Fatal(err)
	}

	params, _ := json.Marshal(fileTypeArgs{Path: tmpFile})
	cmd := &FileTypeCommand{}
	result := cmd.Execute(structs.Task{Params: string(params)})

	if result.Status != "completed" {
		t.Fatalf("expected completed, got %s: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "Windows PE") {
		t.Fatalf("expected Windows PE, got: %s", result.Output)
	}
}

func TestFileTypeELFMagic(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "test.elf")
	data := []byte{0x7F, 0x45, 0x4C, 0x46, 0x02, 0x01, 0x01, 0x00}
	if err := os.WriteFile(tmpFile, data, 0644); err != nil {
		t.Fatal(err)
	}

	params, _ := json.Marshal(fileTypeArgs{Path: tmpFile})
	cmd := &FileTypeCommand{}
	result := cmd.Execute(structs.Task{Params: string(params)})

	if result.Status != "completed" {
		t.Fatalf("expected completed, got %s: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "ELF") {
		t.Fatalf("expected ELF, got: %s", result.Output)
	}
}

func TestFileTypePDFMagic(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "test.pdf")
	data := []byte("%PDF-1.4 test document\n")
	if err := os.WriteFile(tmpFile, data, 0644); err != nil {
		t.Fatal(err)
	}

	params, _ := json.Marshal(fileTypeArgs{Path: tmpFile})
	cmd := &FileTypeCommand{}
	result := cmd.Execute(structs.Task{Params: string(params)})

	if result.Status != "completed" {
		t.Fatalf("expected completed, got %s: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "PDF") {
		t.Fatalf("expected PDF, got: %s", result.Output)
	}
}

func TestFileTypePNGMagic(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "test.png")
	data := []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00}
	if err := os.WriteFile(tmpFile, data, 0644); err != nil {
		t.Fatal(err)
	}

	params, _ := json.Marshal(fileTypeArgs{Path: tmpFile})
	cmd := &FileTypeCommand{}
	result := cmd.Execute(structs.Task{Params: string(params)})

	if result.Status != "completed" {
		t.Fatalf("expected completed, got %s: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "PNG") {
		t.Fatalf("expected PNG, got: %s", result.Output)
	}
}

func TestFileTypeDirectory(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "a.txt"), []byte("text content here\n"), 0644)
	os.WriteFile(filepath.Join(dir, "b.exe"), []byte{0x4D, 0x5A, 0x90, 0x00}, 0644)
	os.WriteFile(filepath.Join(dir, "c.bin"), []byte{0x00, 0x01, 0x02, 0x03}, 0644)

	params, _ := json.Marshal(fileTypeArgs{Path: dir})
	cmd := &FileTypeCommand{}
	result := cmd.Execute(structs.Task{Params: string(params)})

	if result.Status != "completed" {
		t.Fatalf("expected completed, got %s: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "3 files analyzed") {
		t.Fatalf("expected 3 files analyzed, got: %s", result.Output)
	}
}

func TestFileTypeMaxFiles(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 5; i++ {
		os.WriteFile(filepath.Join(dir, fmt.Sprintf("file%d.txt", i)), []byte("test\n"), 0644)
	}

	params, _ := json.Marshal(fileTypeArgs{Path: dir, MaxFiles: 2})
	cmd := &FileTypeCommand{}
	result := cmd.Execute(structs.Task{Params: string(params)})

	if result.Status != "completed" {
		t.Fatalf("expected completed, got %s: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "2 files analyzed") {
		t.Fatalf("expected 2 files analyzed, got: %s", result.Output)
	}
}

func TestMatchMagic(t *testing.T) {
	tests := []struct {
		name     string
		header   []byte
		wantDesc string
		wantCat  string
	}{
		{"MZ", []byte{0x4D, 0x5A, 0x90, 0x00}, "Windows PE", "executable"},
		{"ELF", []byte{0x7F, 0x45, 0x4C, 0x46}, "ELF", "executable"},
		{"ZIP", []byte{0x50, 0x4B, 0x03, 0x04}, "ZIP", "archive"},
		{"GZIP", []byte{0x1F, 0x8B, 0x08, 0x00}, "Gzip", "archive"},
		{"PDF", []byte{0x25, 0x50, 0x44, 0x46}, "PDF", "document"},
		{"PNG", []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}, "PNG", "image"},
		{"JPEG", []byte{0xFF, 0xD8, 0xFF, 0xE0}, "JPEG", "image"},
		{"empty", []byte{}, "", ""},
		{"short", []byte{0xFF}, "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			desc, _, cat := matchMagic(tt.header)
			if tt.wantDesc != "" && !strings.Contains(desc, tt.wantDesc) {
				t.Errorf("matchMagic desc = %q, want contains %q", desc, tt.wantDesc)
			}
			if cat != tt.wantCat {
				t.Errorf("matchMagic cat = %q, want %q", cat, tt.wantCat)
			}
		})
	}
}

func TestIsLikelyText(t *testing.T) {
	if !isLikelyText([]byte("Hello, world!\n")) {
		t.Error("expected text for ASCII content")
	}
	if !isLikelyText([]byte{}) {
		t.Error("expected text for empty data")
	}
	if isLikelyText([]byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0xFF}) {
		t.Error("expected non-text for binary data")
	}
}
