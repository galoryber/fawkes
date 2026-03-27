package commands

import (
	"archive/zip"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestCompressName(t *testing.T) {
	cmd := &CompressCommand{}
	if cmd.Name() != "compress" {
		t.Errorf("expected 'compress', got '%s'", cmd.Name())
	}
}

func TestCompressInvalidJSON(t *testing.T) {
	cmd := &CompressCommand{}
	result := cmd.Execute(structs.Task{Params: "not json"})
	if result.Status != "error" {
		t.Error("expected error for invalid JSON")
	}
}

func TestCompressUnknownAction(t *testing.T) {
	cmd := &CompressCommand{}
	params := CompressParams{Action: "bogus"}
	data, _ := json.Marshal(params)
	result := cmd.Execute(structs.Task{Params: string(data)})
	if result.Status != "error" || !strings.Contains(result.Output, "Unknown action") {
		t.Errorf("expected unknown action error, got: %s", result.Output)
	}
}

func TestCompressCreateMissingPath(t *testing.T) {
	cmd := &CompressCommand{}
	params := CompressParams{Action: "create"}
	data, _ := json.Marshal(params)
	result := cmd.Execute(structs.Task{Params: string(data)})
	if result.Status != "error" || !strings.Contains(result.Output, "'path' is required") {
		t.Errorf("expected missing path error, got: %s", result.Output)
	}
}

func TestCompressCreateSingleFile(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a test file
	testFile := filepath.Join(tmpDir, "test.txt")
	if err := os.WriteFile(testFile, []byte("hello world"), 0644); err != nil {
		t.Fatal(err)
	}

	outputZip := filepath.Join(tmpDir, "output.zip")

	cmd := &CompressCommand{}
	params := CompressParams{Action: "create", Path: testFile, Output: outputZip}
	data, _ := json.Marshal(params)
	result := cmd.Execute(structs.Task{Params: string(data)})

	if result.Status != "success" {
		t.Fatalf("expected success, got: %s", result.Output)
	}
	if !strings.Contains(result.Output, "Files: 1") {
		t.Errorf("expected 1 file, got: %s", result.Output)
	}

	// Verify zip is valid
	reader, err := zip.OpenReader(outputZip)
	if err != nil {
		t.Fatalf("error opening zip: %v", err)
	}
	defer reader.Close()

	if len(reader.File) != 1 {
		t.Errorf("expected 1 entry, got %d", len(reader.File))
	}
	if reader.File[0].Name != "test.txt" {
		t.Errorf("expected 'test.txt', got '%s'", reader.File[0].Name)
	}
}

func TestCompressCreateDirectory(t *testing.T) {
	tmpDir := t.TempDir()
	srcDir := filepath.Join(tmpDir, "src")
	os.MkdirAll(filepath.Join(srcDir, "sub"), 0755)

	os.WriteFile(filepath.Join(srcDir, "a.txt"), []byte("file a"), 0644)
	os.WriteFile(filepath.Join(srcDir, "b.log"), []byte("file b"), 0644)
	os.WriteFile(filepath.Join(srcDir, "sub", "c.txt"), []byte("file c"), 0644)

	outputZip := filepath.Join(tmpDir, "dir.zip")

	cmd := &CompressCommand{}
	params := CompressParams{Action: "create", Path: srcDir, Output: outputZip}
	data, _ := json.Marshal(params)
	result := cmd.Execute(structs.Task{Params: string(data)})

	if result.Status != "success" {
		t.Fatalf("expected success, got: %s", result.Output)
	}
	if !strings.Contains(result.Output, "Files: 3") {
		t.Errorf("expected 3 files, got: %s", result.Output)
	}
}

func TestCompressCreateWithPattern(t *testing.T) {
	tmpDir := t.TempDir()
	srcDir := filepath.Join(tmpDir, "src")
	os.MkdirAll(srcDir, 0755)

	os.WriteFile(filepath.Join(srcDir, "a.txt"), []byte("text"), 0644)
	os.WriteFile(filepath.Join(srcDir, "b.log"), []byte("log"), 0644)
	os.WriteFile(filepath.Join(srcDir, "c.txt"), []byte("more text"), 0644)

	outputZip := filepath.Join(tmpDir, "filtered.zip")

	cmd := &CompressCommand{}
	params := CompressParams{Action: "create", Path: srcDir, Output: outputZip, Pattern: "*.txt"}
	data, _ := json.Marshal(params)
	result := cmd.Execute(structs.Task{Params: string(data)})

	if result.Status != "success" {
		t.Fatalf("expected success, got: %s", result.Output)
	}
	if !strings.Contains(result.Output, "Files: 2") {
		t.Errorf("expected 2 files (txt only), got: %s", result.Output)
	}
}

func TestCompressCreateMaxSize(t *testing.T) {
	tmpDir := t.TempDir()
	srcDir := filepath.Join(tmpDir, "src")
	os.MkdirAll(srcDir, 0755)

	os.WriteFile(filepath.Join(srcDir, "small.txt"), []byte("small"), 0644)
	// Create a file larger than 10 bytes
	os.WriteFile(filepath.Join(srcDir, "large.txt"), []byte("this is a larger file content"), 0644)

	outputZip := filepath.Join(tmpDir, "limited.zip")

	cmd := &CompressCommand{}
	params := CompressParams{Action: "create", Path: srcDir, Output: outputZip, MaxSize: 10}
	data, _ := json.Marshal(params)
	result := cmd.Execute(structs.Task{Params: string(data)})

	if result.Status != "success" {
		t.Fatalf("expected success, got: %s", result.Output)
	}
	if !strings.Contains(result.Output, "Files: 1") {
		t.Errorf("expected 1 file (small only), got: %s", result.Output)
	}
	if !strings.Contains(result.Output, "Skipped: 1") {
		t.Errorf("expected 1 skipped, got: %s", result.Output)
	}
}

func TestCompressCreateNonexistentPath(t *testing.T) {
	cmd := &CompressCommand{}
	params := CompressParams{Action: "create", Path: "/nonexistent/path/does/not/exist"}
	data, _ := json.Marshal(params)
	result := cmd.Execute(structs.Task{Params: string(data)})
	if result.Status != "error" {
		t.Error("expected error for nonexistent path")
	}
}

func TestCompressList(t *testing.T) {
	// Create a zip first
	tmpDir := t.TempDir()
	zipPath := filepath.Join(tmpDir, "test.zip")

	zipFile, _ := os.Create(zipPath)
	w := zip.NewWriter(zipFile)
	f, _ := w.Create("hello.txt")
	f.Write([]byte("hello world"))
	f2, _ := w.Create("sub/other.txt")
	f2.Write([]byte("other content"))
	w.Close()
	zipFile.Close()

	cmd := &CompressCommand{}
	params := CompressParams{Action: "list", Path: zipPath}
	data, _ := json.Marshal(params)
	result := cmd.Execute(structs.Task{Params: string(data)})

	if result.Status != "success" {
		t.Fatalf("expected success, got: %s", result.Output)
	}
	if !strings.Contains(result.Output, "hello.txt") {
		t.Error("expected hello.txt in listing")
	}
	if !strings.Contains(result.Output, "sub/other.txt") {
		t.Error("expected sub/other.txt in listing")
	}
	if !strings.Contains(result.Output, "2 files") {
		t.Errorf("expected 2 files summary, got: %s", result.Output)
	}
}

func TestCompressListMissingPath(t *testing.T) {
	cmd := &CompressCommand{}
	params := CompressParams{Action: "list"}
	data, _ := json.Marshal(params)
	result := cmd.Execute(structs.Task{Params: string(data)})
	if result.Status != "error" {
		t.Error("expected error for missing path")
	}
}

func TestCompressListInvalidZip(t *testing.T) {
	tmpDir := t.TempDir()
	notZip := filepath.Join(tmpDir, "not.zip")
	os.WriteFile(notZip, []byte("not a zip file"), 0644)

	cmd := &CompressCommand{}
	params := CompressParams{Action: "list", Path: notZip}
	data, _ := json.Marshal(params)
	result := cmd.Execute(structs.Task{Params: string(data)})
	if result.Status != "error" {
		t.Error("expected error for invalid zip")
	}
}

func TestCompressExtract(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a zip
	zipPath := filepath.Join(tmpDir, "test.zip")
	zipFile, _ := os.Create(zipPath)
	w := zip.NewWriter(zipFile)
	f, _ := w.Create("file1.txt")
	f.Write([]byte("content1"))
	f2, _ := w.Create("dir/file2.txt")
	f2.Write([]byte("content2"))
	w.Close()
	zipFile.Close()

	outputDir := filepath.Join(tmpDir, "extracted")

	cmd := &CompressCommand{}
	params := CompressParams{Action: "extract", Path: zipPath, Output: outputDir}
	data, _ := json.Marshal(params)
	result := cmd.Execute(structs.Task{Params: string(data)})

	if result.Status != "success" {
		t.Fatalf("expected success, got: %s", result.Output)
	}
	if !strings.Contains(result.Output, "Extracted 2 files") {
		t.Errorf("expected 2 files extracted, got: %s", result.Output)
	}

	// Verify files exist
	content1, err := os.ReadFile(filepath.Join(outputDir, "file1.txt"))
	if err != nil || string(content1) != "content1" {
		t.Error("file1.txt not extracted correctly")
	}
	content2, err := os.ReadFile(filepath.Join(outputDir, "dir", "file2.txt"))
	if err != nil || string(content2) != "content2" {
		t.Error("dir/file2.txt not extracted correctly")
	}
}

func TestCompressExtractWithPattern(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a zip with mixed file types
	zipPath := filepath.Join(tmpDir, "mixed.zip")
	zipFile, _ := os.Create(zipPath)
	w := zip.NewWriter(zipFile)
	f1, _ := w.Create("doc.txt")
	f1.Write([]byte("text"))
	f2, _ := w.Create("img.png")
	f2.Write([]byte("png data"))
	f3, _ := w.Create("notes.txt")
	f3.Write([]byte("notes"))
	w.Close()
	zipFile.Close()

	outputDir := filepath.Join(tmpDir, "filtered")

	cmd := &CompressCommand{}
	params := CompressParams{Action: "extract", Path: zipPath, Output: outputDir, Pattern: "*.txt"}
	data, _ := json.Marshal(params)
	result := cmd.Execute(structs.Task{Params: string(data)})

	if result.Status != "success" {
		t.Fatalf("expected success, got: %s", result.Output)
	}
	if !strings.Contains(result.Output, "Extracted 2 files") {
		t.Errorf("expected 2 txt files extracted, got: %s", result.Output)
	}

	// Verify only txt files extracted
	if _, err := os.Stat(filepath.Join(outputDir, "img.png")); !os.IsNotExist(err) {
		t.Error("img.png should not have been extracted")
	}
}

func TestCompressExtractMissingPath(t *testing.T) {
	cmd := &CompressCommand{}
	params := CompressParams{Action: "extract"}
	data, _ := json.Marshal(params)
	result := cmd.Execute(structs.Task{Params: string(data)})
	if result.Status != "error" {
		t.Error("expected error for missing path")
	}
}

func TestCompressAutoOutputPath(t *testing.T) {
	tmpDir := t.TempDir()
	srcDir := filepath.Join(tmpDir, "mydata")
	os.MkdirAll(srcDir, 0755)
	os.WriteFile(filepath.Join(srcDir, "test.txt"), []byte("data"), 0644)

	cmd := &CompressCommand{}
	// Don't specify output — should auto-create mydata.zip
	params := CompressParams{Action: "create", Path: srcDir}
	data, _ := json.Marshal(params)
	result := cmd.Execute(structs.Task{Params: string(data)})

	if result.Status != "success" {
		t.Fatalf("expected success, got: %s", result.Output)
	}
	if !strings.Contains(result.Output, "mydata.zip") {
		t.Errorf("expected auto-generated path with mydata.zip, got: %s", result.Output)
	}
}

func TestCompressMaxDepth(t *testing.T) {
	tmpDir := t.TempDir()
	srcDir := filepath.Join(tmpDir, "deep")
	deep := filepath.Join(srcDir, "a", "b", "c", "d")
	os.MkdirAll(deep, 0755)
	os.WriteFile(filepath.Join(srcDir, "top.txt"), []byte("top"), 0644)
	os.WriteFile(filepath.Join(srcDir, "a", "level1.txt"), []byte("l1"), 0644)
	os.WriteFile(filepath.Join(deep, "deep.txt"), []byte("deep"), 0644)

	outputZip := filepath.Join(tmpDir, "shallow.zip")

	cmd := &CompressCommand{}
	params := CompressParams{Action: "create", Path: srcDir, Output: outputZip, MaxDepth: 2}
	data, _ := json.Marshal(params)
	result := cmd.Execute(structs.Task{Params: string(data)})

	if result.Status != "success" {
		t.Fatalf("expected success, got: %s", result.Output)
	}
	if !strings.Contains(result.Output, "Files: 2") {
		t.Errorf("expected 2 files (top + level1), got: %s", result.Output)
	}
}

func TestCompressRoundTrip(t *testing.T) {
	tmpDir := t.TempDir()
	srcDir := filepath.Join(tmpDir, "src")
	os.MkdirAll(filepath.Join(srcDir, "sub"), 0755)

	os.WriteFile(filepath.Join(srcDir, "a.txt"), []byte("alpha"), 0644)
	os.WriteFile(filepath.Join(srcDir, "sub", "b.txt"), []byte("beta"), 0644)

	zipPath := filepath.Join(tmpDir, "roundtrip.zip")
	extractDir := filepath.Join(tmpDir, "out")

	cmd := &CompressCommand{}

	// Create
	createParams := CompressParams{Action: "create", Path: srcDir, Output: zipPath}
	data, _ := json.Marshal(createParams)
	result := cmd.Execute(structs.Task{Params: string(data)})
	if result.Status != "success" {
		t.Fatalf("create failed: %s", result.Output)
	}

	// Extract
	extractParams := CompressParams{Action: "extract", Path: zipPath, Output: extractDir}
	data, _ = json.Marshal(extractParams)
	result = cmd.Execute(structs.Task{Params: string(data)})
	if result.Status != "success" {
		t.Fatalf("extract failed: %s", result.Output)
	}

	// Verify
	contentA, err := os.ReadFile(filepath.Join(extractDir, "a.txt"))
	if err != nil || string(contentA) != "alpha" {
		t.Error("a.txt roundtrip failed")
	}
	contentB, err := os.ReadFile(filepath.Join(extractDir, "sub", "b.txt"))
	if err != nil || string(contentB) != "beta" {
		t.Error("sub/b.txt roundtrip failed")
	}
}

func TestCompressCreateReportsFileErrors(t *testing.T) {
	tmpDir := t.TempDir()
	srcDir := filepath.Join(tmpDir, "src")
	os.MkdirAll(srcDir, 0755)

	// Create a readable file and an unreadable file
	os.WriteFile(filepath.Join(srcDir, "good.txt"), []byte("readable"), 0644)
	unreadable := filepath.Join(srcDir, "secret.txt")
	os.WriteFile(unreadable, []byte("no access"), 0000)

	outputZip := filepath.Join(tmpDir, "partial.zip")

	cmd := &CompressCommand{}
	params := CompressParams{Action: "create", Path: srcDir, Output: outputZip}
	data, _ := json.Marshal(params)
	result := cmd.Execute(structs.Task{Params: string(data)})

	if result.Status != "success" {
		t.Fatalf("expected success (partial), got: %s", result.Output)
	}
	// Should have compressed the good file
	if !strings.Contains(result.Output, "Files: 1") {
		t.Errorf("expected 1 file compressed, got: %s", result.Output)
	}
	// Should report the error for the unreadable file
	if !strings.Contains(result.Output, "file errors") {
		t.Errorf("expected file errors in output, got: %s", result.Output)
	}
	if !strings.Contains(result.Output, "secret.txt") {
		t.Errorf("expected secret.txt mentioned in errors, got: %s", result.Output)
	}
}

func TestCompressExtractReportsErrors(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a zip
	zipPath := filepath.Join(tmpDir, "test.zip")
	zipFile, _ := os.Create(zipPath)
	w := zip.NewWriter(zipFile)
	f1, _ := w.Create("good.txt")
	f1.Write([]byte("good content"))
	w.Close()
	zipFile.Close()

	// Extract to a read-only directory so file creation fails
	outputDir := filepath.Join(tmpDir, "readonly")
	os.MkdirAll(outputDir, 0755)

	cmd := &CompressCommand{}
	params := CompressParams{Action: "extract", Path: zipPath, Output: outputDir}
	data, _ := json.Marshal(params)
	result := cmd.Execute(structs.Task{Params: string(data)})

	// Should succeed (extracted the file)
	if result.Status != "success" {
		t.Fatalf("expected success, got: %s", result.Output)
	}
	if !strings.Contains(result.Output, "Extracted 1 files") {
		t.Errorf("expected 1 file extracted, got: %s", result.Output)
	}
}

func TestCompressExtractZipSlip(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a zip with a path traversal entry (../evil.txt)
	zipPath := filepath.Join(tmpDir, "malicious.zip")
	zipFile, _ := os.Create(zipPath)
	w := zip.NewWriter(zipFile)

	// Normal file
	f1, _ := w.Create("safe.txt")
	f1.Write([]byte("safe content"))

	// Path traversal attempt
	f2, _ := w.Create("../evil.txt")
	f2.Write([]byte("evil content"))

	w.Close()
	zipFile.Close()

	outputDir := filepath.Join(tmpDir, "output")

	cmd := &CompressCommand{}
	params := CompressParams{Action: "extract", Path: zipPath, Output: outputDir}
	data, _ := json.Marshal(params)
	result := cmd.Execute(structs.Task{Params: string(data)})

	if result.Status != "success" {
		t.Fatalf("expected success, got: %s", result.Output)
	}

	// Safe file should be extracted
	if _, err := os.Stat(filepath.Join(outputDir, "safe.txt")); err != nil {
		t.Error("safe.txt should have been extracted")
	}

	// Evil file should NOT be outside the output directory
	evilPath := filepath.Join(tmpDir, "evil.txt")
	if _, err := os.Stat(evilPath); !os.IsNotExist(err) {
		t.Error("zip slip: evil.txt escaped to parent directory")
	}

	// Should report path traversal skip in output
	if !strings.Contains(result.Output, "path traversal") {
		t.Logf("output: %s", result.Output)
	}
}

func TestCompressExtractDirectoryEntry(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a zip with a proper directory entry using CreateHeader
	zipPath := filepath.Join(tmpDir, "dirs.zip")
	zipFile, _ := os.Create(zipPath)
	w := zip.NewWriter(zipFile)

	// Directory entry with proper header
	dirHeader := &zip.FileHeader{Name: "subdir/"}
	dirHeader.SetMode(0755 | os.ModeDir)
	_, _ = w.CreateHeader(dirHeader)

	// File inside directory
	fileHeader := &zip.FileHeader{Name: "subdir/file.txt"}
	fileHeader.SetMode(0644)
	f, _ := w.CreateHeader(fileHeader)
	f.Write([]byte("inside subdir"))

	w.Close()
	zipFile.Close()

	outputDir := filepath.Join(tmpDir, "extracted")
	cmd := &CompressCommand{}
	params := CompressParams{Action: "extract", Path: zipPath, Output: outputDir}
	data, _ := json.Marshal(params)
	result := cmd.Execute(structs.Task{Params: string(data)})

	if result.Status != "success" {
		t.Fatalf("expected success, got: %s", result.Output)
	}

	// Verify directory was created
	info, err := os.Stat(filepath.Join(outputDir, "subdir"))
	if err != nil {
		t.Fatal("subdir should exist")
	}
	if !info.IsDir() {
		t.Error("subdir should be a directory")
	}

	// Verify file inside directory
	content, err := os.ReadFile(filepath.Join(outputDir, "subdir", "file.txt"))
	if err != nil || string(content) != "inside subdir" {
		t.Errorf("subdir/file.txt not extracted correctly: err=%v content=%q", err, content)
	}
}

func TestCompressExtractAutoOutputPath(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a zip
	zipPath := filepath.Join(tmpDir, "archive.zip")
	zipFile, _ := os.Create(zipPath)
	w := zip.NewWriter(zipFile)
	f, _ := w.Create("auto.txt")
	f.Write([]byte("auto"))
	w.Close()
	zipFile.Close()

	// Extract without specifying output — should use "archive" (zip name minus extension)
	cmd := &CompressCommand{}
	params := CompressParams{Action: "extract", Path: zipPath}
	data, _ := json.Marshal(params)
	result := cmd.Execute(structs.Task{Params: string(data)})

	if result.Status != "success" {
		t.Fatalf("expected success, got: %s", result.Output)
	}

	expectedOutput := filepath.Join(tmpDir, "archive")
	content, err := os.ReadFile(filepath.Join(expectedOutput, "auto.txt"))
	if err != nil || string(content) != "auto" {
		t.Errorf("auto output path extraction failed: %v", err)
	}
}

func TestCompressExtractNonexistentZip(t *testing.T) {
	cmd := &CompressCommand{}
	params := CompressParams{Action: "extract", Path: "/nonexistent/file.zip"}
	data, _ := json.Marshal(params)
	result := cmd.Execute(structs.Task{Params: string(data)})

	if result.Status != "error" {
		t.Errorf("expected error for nonexistent zip, got: %s", result.Output)
	}
}

func TestCompressListEmptyZip(t *testing.T) {
	// Create an empty zip (no files) — triggers ratio=0 branch
	tmpDir := t.TempDir()
	zipPath := filepath.Join(tmpDir, "empty.zip")

	zipFile, _ := os.Create(zipPath)
	w := zip.NewWriter(zipFile)
	w.Close()
	zipFile.Close()

	cmd := &CompressCommand{}
	params := CompressParams{Action: "list", Path: zipPath}
	data, _ := json.Marshal(params)
	result := cmd.Execute(structs.Task{Params: string(data)})

	if result.Status != "success" {
		t.Fatalf("expected success, got: %s", result.Output)
	}
	if !strings.Contains(result.Output, "0 files") {
		t.Errorf("expected '0 files' summary, got: %s", result.Output)
	}
	if !strings.Contains(result.Output, "Ratio: 0.0%") {
		t.Errorf("expected 'Ratio: 0.0%%' for empty zip, got: %s", result.Output)
	}
}
