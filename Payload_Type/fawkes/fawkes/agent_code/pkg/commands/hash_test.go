package commands

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestHashName(t *testing.T) {
	cmd := &HashCommand{}
	if cmd.Name() != "hash" {
		t.Errorf("Expected 'hash', got '%s'", cmd.Name())
	}
}

func TestHashDescription(t *testing.T) {
	cmd := &HashCommand{}
	if cmd.Description() == "" {
		t.Error("Description should not be empty")
	}
}

func TestHashEmptyParams(t *testing.T) {
	cmd := &HashCommand{}
	result := cmd.Execute(structs.Task{Params: ""})
	if result.Status != "error" {
		t.Error("Expected error for empty params")
	}
}

func TestHashBadJSON(t *testing.T) {
	cmd := &HashCommand{}
	result := cmd.Execute(structs.Task{Params: "not json"})
	if result.Status != "error" {
		t.Error("Expected error for bad JSON")
	}
}

func TestHashMissingPath(t *testing.T) {
	cmd := &HashCommand{}
	params, _ := json.Marshal(hashArgs{Algorithm: "sha256"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" || !strings.Contains(result.Output, "path parameter is required") {
		t.Errorf("Expected missing path error, got: %s", result.Output)
	}
}

func TestHashInvalidAlgorithm(t *testing.T) {
	cmd := &HashCommand{}
	params, _ := json.Marshal(hashArgs{Path: "/tmp", Algorithm: "blake2"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" || !strings.Contains(result.Output, "unsupported algorithm") {
		t.Errorf("Expected unsupported algorithm error, got: %s", result.Output)
	}
}

func TestHashNonexistentPath(t *testing.T) {
	cmd := &HashCommand{}
	params, _ := json.Marshal(hashArgs{Path: "/nonexistent/path/abc123"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Error("Expected error for nonexistent path")
	}
}

func TestHashSingleFile(t *testing.T) {
	// Create temp file with known content
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.txt")
	content := []byte("hello world")
	if err := os.WriteFile(testFile, content, 0644); err != nil {
		t.Fatal(err)
	}

	// Expected SHA-256
	h := sha256.Sum256(content)
	expectedHash := hex.EncodeToString(h[:])

	cmd := &HashCommand{}
	params, _ := json.Marshal(hashArgs{Path: testFile, Algorithm: "sha256"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Fatalf("Expected success, got: %s — %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, expectedHash) {
		t.Errorf("Expected hash %s in output, got:\n%s", expectedHash, result.Output)
	}
	if !strings.Contains(result.Output, "1 files hashed") {
		t.Errorf("Expected '1 files hashed' in output, got:\n%s", result.Output)
	}
}

func TestHashAlgorithms(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.txt")
	content := []byte("test data for hashing")
	if err := os.WriteFile(testFile, content, 0644); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		alg      string
		expected string
	}{
		{"md5", hex.EncodeToString(func() []byte { h := md5.Sum(content); return h[:] }())},
		{"sha1", hex.EncodeToString(func() []byte { h := sha1.Sum(content); return h[:] }())},
		{"sha256", hex.EncodeToString(func() []byte { h := sha256.Sum256(content); return h[:] }())},
		{"sha512", hex.EncodeToString(func() []byte { h := sha512.Sum512(content); return h[:] }())},
	}

	cmd := &HashCommand{}
	for _, tc := range tests {
		t.Run(tc.alg, func(t *testing.T) {
			params, _ := json.Marshal(hashArgs{Path: testFile, Algorithm: tc.alg})
			result := cmd.Execute(structs.Task{Params: string(params)})
			if result.Status != "success" {
				t.Fatalf("Expected success for %s, got: %s — %s", tc.alg, result.Status, result.Output)
			}
			if !strings.Contains(result.Output, tc.expected) {
				t.Errorf("Expected %s hash %s in output, got:\n%s", tc.alg, tc.expected, result.Output)
			}
		})
	}
}

func TestHashDefaultAlgorithm(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.txt")
	content := []byte("default algo test")
	if err := os.WriteFile(testFile, content, 0644); err != nil {
		t.Fatal(err)
	}

	// Default should be sha256
	h := sha256.Sum256(content)
	expectedHash := hex.EncodeToString(h[:])

	cmd := &HashCommand{}
	params, _ := json.Marshal(hashArgs{Path: testFile})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Fatalf("Expected success, got: %s", result.Output)
	}
	if !strings.Contains(result.Output, expectedHash) {
		t.Errorf("Expected sha256 hash by default, got:\n%s", result.Output)
	}
	if !strings.Contains(result.Output, "SHA256") {
		t.Errorf("Expected SHA256 label in output, got:\n%s", result.Output)
	}
}

func TestHashDirectory(t *testing.T) {
	tmpDir := t.TempDir()
	for i := 0; i < 3; i++ {
		if err := os.WriteFile(filepath.Join(tmpDir, fmt.Sprintf("file%d.txt", i)), []byte(fmt.Sprintf("content%d", i)), 0644); err != nil {
			t.Fatal(err)
		}
	}

	cmd := &HashCommand{}
	params, _ := json.Marshal(hashArgs{Path: tmpDir, Algorithm: "md5"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Fatalf("Expected success, got: %s — %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "3 files hashed") {
		t.Errorf("Expected '3 files hashed', got:\n%s", result.Output)
	}
}

func TestHashDirectoryRecursive(t *testing.T) {
	tmpDir := t.TempDir()
	subDir := filepath.Join(tmpDir, "sub")
	if err := os.Mkdir(subDir, 0755); err != nil {
		t.Fatal(err)
	}

	// Root file
	os.WriteFile(filepath.Join(tmpDir, "root.txt"), []byte("root"), 0644)
	// Subdir file
	os.WriteFile(filepath.Join(subDir, "sub.txt"), []byte("sub"), 0644)

	cmd := &HashCommand{}

	// Non-recursive: should only get root file
	params, _ := json.Marshal(hashArgs{Path: tmpDir, Recursive: false})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if !strings.Contains(result.Output, "1 files hashed") {
		t.Errorf("Non-recursive should find 1 file, got:\n%s", result.Output)
	}

	// Recursive: should get both
	params, _ = json.Marshal(hashArgs{Path: tmpDir, Recursive: true})
	result = cmd.Execute(structs.Task{Params: string(params)})
	if !strings.Contains(result.Output, "2 files hashed") {
		t.Errorf("Recursive should find 2 files, got:\n%s", result.Output)
	}
}

func TestHashPatternFilter(t *testing.T) {
	tmpDir := t.TempDir()
	os.WriteFile(filepath.Join(tmpDir, "test.txt"), []byte("text"), 0644)
	os.WriteFile(filepath.Join(tmpDir, "test.exe"), []byte("exe"), 0644)
	os.WriteFile(filepath.Join(tmpDir, "test.dll"), []byte("dll"), 0644)

	cmd := &HashCommand{}
	params, _ := json.Marshal(hashArgs{Path: tmpDir, Pattern: "*.exe"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Fatalf("Expected success, got: %s", result.Output)
	}
	if !strings.Contains(result.Output, "1 files hashed") {
		t.Errorf("Expected 1 file with *.exe pattern, got:\n%s", result.Output)
	}
	if !strings.Contains(result.Output, "test.exe") {
		t.Errorf("Expected test.exe in output, got:\n%s", result.Output)
	}
}

func TestHashMaxFiles(t *testing.T) {
	tmpDir := t.TempDir()
	for i := 0; i < 10; i++ {
		os.WriteFile(filepath.Join(tmpDir, fmt.Sprintf("file%02d.txt", i)), []byte(fmt.Sprintf("content%d", i)), 0644)
	}

	cmd := &HashCommand{}
	params, _ := json.Marshal(hashArgs{Path: tmpDir, MaxFiles: 3})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Fatalf("Expected success, got: %s", result.Output)
	}
	if !strings.Contains(result.Output, "3 files hashed") {
		t.Errorf("Expected max 3 files, got:\n%s", result.Output)
	}
}

func TestHashFormatSize(t *testing.T) {
	tests := []struct {
		bytes    int64
		expected string
	}{
		{0, "0 B"},
		{512, "512 B"},
		{1024, "1.0 KB"},
		{1536, "1.5 KB"},
		{1048576, "1.0 MB"},
		{1073741824, "1.0 GB"},
	}

	for _, tc := range tests {
		result := hashFormatSize(tc.bytes)
		if result != tc.expected {
			t.Errorf("hashFormatSize(%d) = %s, want %s", tc.bytes, result, tc.expected)
		}
	}
}

func TestHashValidAlgorithm(t *testing.T) {
	valid := []string{"md5", "sha1", "sha256", "sha512"}
	invalid := []string{"blake2", "crc32", "ripemd160", ""}

	for _, alg := range valid {
		if !hashValidAlgorithm(alg) {
			t.Errorf("%s should be valid", alg)
		}
	}
	for _, alg := range invalid {
		if hashValidAlgorithm(alg) {
			t.Errorf("%s should be invalid", alg)
		}
	}
}

func TestHashOutputFormat(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.txt")
	os.WriteFile(testFile, []byte("output format test"), 0644)

	cmd := &HashCommand{}
	params, _ := json.Marshal(hashArgs{Path: testFile, Algorithm: "md5"})
	result := cmd.Execute(structs.Task{Params: string(params)})

	if !strings.Contains(result.Output, "MD5 hashes") {
		t.Errorf("Expected 'MD5 hashes' header, got:\n%s", result.Output)
	}
	if !strings.Contains(result.Output, "----") {
		t.Errorf("Expected separator line, got:\n%s", result.Output)
	}
	if !strings.Contains(result.Output, "files hashed") {
		t.Errorf("Expected summary line, got:\n%s", result.Output)
	}
}

func TestHashEmptyFile(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "empty.txt")
	os.WriteFile(testFile, []byte{}, 0644)

	// SHA-256 of empty content
	h := sha256.Sum256([]byte{})
	expectedHash := hex.EncodeToString(h[:])

	cmd := &HashCommand{}
	params, _ := json.Marshal(hashArgs{Path: testFile})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Fatalf("Expected success for empty file, got: %s", result.Output)
	}
	if !strings.Contains(result.Output, expectedHash) {
		t.Errorf("Expected hash of empty file, got:\n%s", result.Output)
	}
	if !strings.Contains(result.Output, "0 B") {
		t.Errorf("Expected '0 B' size for empty file, got:\n%s", result.Output)
	}
}
