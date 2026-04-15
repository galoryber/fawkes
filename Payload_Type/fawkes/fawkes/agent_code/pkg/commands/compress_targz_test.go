package commands

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestTarGzCreateSingleFile(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.txt")
	if err := os.WriteFile(testFile, []byte("hello world"), 0644); err != nil {
		t.Fatal(err)
	}

	outputPath := filepath.Join(tmpDir, "output.tar.gz")

	cmd := &CompressCommand{}
	params := CompressParams{Action: "create", Path: testFile, Output: outputPath, Format: formatTarGz}
	data, _ := json.Marshal(params)
	result := cmd.Execute(structs.Task{Params: string(data)})

	if result.Status != "success" {
		t.Fatalf("expected success, got: %s", result.Output)
	}
	if !strings.Contains(result.Output, "Files: 1") {
		t.Errorf("expected 1 file, got: %s", result.Output)
	}
	if !strings.Contains(result.Output, ".tar.gz") {
		t.Errorf("expected tar.gz path in output, got: %s", result.Output)
	}

	// Verify it's a valid tar.gz
	f, err := os.Open(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatalf("not valid gzip: %v", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	hdr, err := tr.Next()
	if err != nil {
		t.Fatalf("not valid tar: %v", err)
	}
	if hdr.Name != "test.txt" {
		t.Errorf("expected 'test.txt', got '%s'", hdr.Name)
	}
}

func TestTarGzCreateDirectory(t *testing.T) {
	tmpDir := t.TempDir()
	srcDir := filepath.Join(tmpDir, "src")
	os.MkdirAll(filepath.Join(srcDir, "sub"), 0755)

	os.WriteFile(filepath.Join(srcDir, "a.txt"), []byte("file a"), 0644)
	os.WriteFile(filepath.Join(srcDir, "b.log"), []byte("file b"), 0644)
	os.WriteFile(filepath.Join(srcDir, "sub", "c.txt"), []byte("file c"), 0644)

	outputPath := filepath.Join(tmpDir, "dir.tar.gz")

	cmd := &CompressCommand{}
	params := CompressParams{Action: "create", Path: srcDir, Output: outputPath, Format: formatTarGz}
	data, _ := json.Marshal(params)
	result := cmd.Execute(structs.Task{Params: string(data)})

	if result.Status != "success" {
		t.Fatalf("expected success, got: %s", result.Output)
	}
	if !strings.Contains(result.Output, "Files: 3") {
		t.Errorf("expected 3 files, got: %s", result.Output)
	}
}

func TestTarGzCreateWithPattern(t *testing.T) {
	tmpDir := t.TempDir()
	srcDir := filepath.Join(tmpDir, "src")
	os.MkdirAll(srcDir, 0755)

	os.WriteFile(filepath.Join(srcDir, "a.txt"), []byte("text"), 0644)
	os.WriteFile(filepath.Join(srcDir, "b.log"), []byte("log"), 0644)
	os.WriteFile(filepath.Join(srcDir, "c.txt"), []byte("more text"), 0644)

	outputPath := filepath.Join(tmpDir, "filtered.tar.gz")

	cmd := &CompressCommand{}
	params := CompressParams{Action: "create", Path: srcDir, Output: outputPath, Format: formatTarGz, Pattern: "*.txt"}
	data, _ := json.Marshal(params)
	result := cmd.Execute(structs.Task{Params: string(data)})

	if result.Status != "success" {
		t.Fatalf("expected success, got: %s", result.Output)
	}
	if !strings.Contains(result.Output, "Files: 2") {
		t.Errorf("expected 2 files (txt only), got: %s", result.Output)
	}
}

func TestTarGzCreateMaxSize(t *testing.T) {
	tmpDir := t.TempDir()
	srcDir := filepath.Join(tmpDir, "src")
	os.MkdirAll(srcDir, 0755)

	os.WriteFile(filepath.Join(srcDir, "small.txt"), []byte("small"), 0644)
	os.WriteFile(filepath.Join(srcDir, "large.txt"), []byte("this is a larger file content"), 0644)

	outputPath := filepath.Join(tmpDir, "limited.tar.gz")

	cmd := &CompressCommand{}
	params := CompressParams{Action: "create", Path: srcDir, Output: outputPath, Format: formatTarGz, MaxSize: 10}
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

func TestTarGzCreateMissingPath(t *testing.T) {
	cmd := &CompressCommand{}
	params := CompressParams{Action: "create", Format: formatTarGz}
	data, _ := json.Marshal(params)
	result := cmd.Execute(structs.Task{Params: string(data)})
	if result.Status != "error" {
		t.Error("expected error for missing path")
	}
}

func TestTarGzCreateNonexistentPath(t *testing.T) {
	cmd := &CompressCommand{}
	params := CompressParams{Action: "create", Path: "/nonexistent/path", Format: formatTarGz}
	data, _ := json.Marshal(params)
	result := cmd.Execute(structs.Task{Params: string(data)})
	if result.Status != "error" {
		t.Error("expected error for nonexistent path")
	}
}

func TestTarGzList(t *testing.T) {
	tmpDir := t.TempDir()
	archivePath := filepath.Join(tmpDir, "test.tar.gz")

	// Create a tar.gz manually
	f, _ := os.Create(archivePath)
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)

	content := []byte("hello world")
	tw.WriteHeader(&tar.Header{Name: "hello.txt", Size: int64(len(content)), Mode: 0644})
	tw.Write(content)

	content2 := []byte("other content")
	tw.WriteHeader(&tar.Header{Name: "sub/other.txt", Size: int64(len(content2)), Mode: 0644})
	tw.Write(content2)

	tw.Close()
	gz.Close()
	f.Close()

	cmd := &CompressCommand{}
	params := CompressParams{Action: "list", Path: archivePath}
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
	if !strings.Contains(result.Output, "2 entries") {
		t.Errorf("expected 2 entries, got: %s", result.Output)
	}
}

func TestTarGzListMissingPath(t *testing.T) {
	cmd := &CompressCommand{}
	params := CompressParams{Action: "list", Format: formatTarGz}
	data, _ := json.Marshal(params)
	result := cmd.Execute(structs.Task{Params: string(data)})
	if result.Status != "error" {
		t.Error("expected error for missing path")
	}
}

func TestTarGzListInvalidArchive(t *testing.T) {
	tmpDir := t.TempDir()
	notTarGz := filepath.Join(tmpDir, "not.tar.gz")
	os.WriteFile(notTarGz, []byte("not a tar.gz"), 0644)

	cmd := &CompressCommand{}
	params := CompressParams{Action: "list", Path: notTarGz}
	data, _ := json.Marshal(params)
	result := cmd.Execute(structs.Task{Params: string(data)})
	if result.Status != "error" {
		t.Error("expected error for invalid tar.gz")
	}
}

func TestTarGzExtract(t *testing.T) {
	tmpDir := t.TempDir()
	archivePath := filepath.Join(tmpDir, "test.tar.gz")

	// Create a tar.gz
	f, _ := os.Create(archivePath)
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)

	content1 := []byte("content1")
	tw.WriteHeader(&tar.Header{Name: "file1.txt", Size: int64(len(content1)), Mode: 0644})
	tw.Write(content1)

	content2 := []byte("content2")
	tw.WriteHeader(&tar.Header{Name: "dir/file2.txt", Size: int64(len(content2)), Mode: 0644})
	tw.Write(content2)

	tw.Close()
	gz.Close()
	f.Close()

	outputDir := filepath.Join(tmpDir, "extracted")

	cmd := &CompressCommand{}
	params := CompressParams{Action: "extract", Path: archivePath, Output: outputDir}
	data, _ := json.Marshal(params)
	result := cmd.Execute(structs.Task{Params: string(data)})

	if result.Status != "success" {
		t.Fatalf("expected success, got: %s", result.Output)
	}
	if !strings.Contains(result.Output, "Extracted 2 files") {
		t.Errorf("expected 2 files extracted, got: %s", result.Output)
	}

	c1, err := os.ReadFile(filepath.Join(outputDir, "file1.txt"))
	if err != nil || string(c1) != "content1" {
		t.Error("file1.txt not extracted correctly")
	}
	c2, err := os.ReadFile(filepath.Join(outputDir, "dir", "file2.txt"))
	if err != nil || string(c2) != "content2" {
		t.Error("dir/file2.txt not extracted correctly")
	}
}

func TestTarGzExtractWithPattern(t *testing.T) {
	tmpDir := t.TempDir()
	archivePath := filepath.Join(tmpDir, "mixed.tar.gz")

	f, _ := os.Create(archivePath)
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)

	for _, entry := range []struct {
		name    string
		content string
	}{
		{"doc.txt", "text"},
		{"img.png", "png data"},
		{"notes.txt", "notes"},
	} {
		tw.WriteHeader(&tar.Header{Name: entry.name, Size: int64(len(entry.content)), Mode: 0644})
		tw.Write([]byte(entry.content))
	}

	tw.Close()
	gz.Close()
	f.Close()

	outputDir := filepath.Join(tmpDir, "filtered")

	cmd := &CompressCommand{}
	params := CompressParams{Action: "extract", Path: archivePath, Output: outputDir, Pattern: "*.txt"}
	data, _ := json.Marshal(params)
	result := cmd.Execute(structs.Task{Params: string(data)})

	if result.Status != "success" {
		t.Fatalf("expected success, got: %s", result.Output)
	}
	if !strings.Contains(result.Output, "Extracted 2 files") {
		t.Errorf("expected 2 txt files extracted, got: %s", result.Output)
	}

	if _, err := os.Stat(filepath.Join(outputDir, "img.png")); !os.IsNotExist(err) {
		t.Error("img.png should not have been extracted")
	}
}

func TestTarGzExtractMissingPath(t *testing.T) {
	cmd := &CompressCommand{}
	params := CompressParams{Action: "extract", Format: formatTarGz}
	data, _ := json.Marshal(params)
	result := cmd.Execute(structs.Task{Params: string(data)})
	if result.Status != "error" {
		t.Error("expected error for missing path")
	}
}

func TestTarGzExtractPathTraversal(t *testing.T) {
	tmpDir := t.TempDir()
	archivePath := filepath.Join(tmpDir, "malicious.tar.gz")

	f, _ := os.Create(archivePath)
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)

	safe := []byte("safe content")
	tw.WriteHeader(&tar.Header{Name: "safe.txt", Size: int64(len(safe)), Mode: 0644})
	tw.Write(safe)

	evil := []byte("evil content")
	tw.WriteHeader(&tar.Header{Name: "../evil.txt", Size: int64(len(evil)), Mode: 0644})
	tw.Write(evil)

	tw.Close()
	gz.Close()
	f.Close()

	outputDir := filepath.Join(tmpDir, "output")

	cmd := &CompressCommand{}
	params := CompressParams{Action: "extract", Path: archivePath, Output: outputDir}
	data, _ := json.Marshal(params)
	result := cmd.Execute(structs.Task{Params: string(data)})

	if result.Status != "success" {
		t.Fatalf("expected success, got: %s", result.Output)
	}

	// Safe file should be extracted
	if _, err := os.Stat(filepath.Join(outputDir, "safe.txt")); err != nil {
		t.Error("safe.txt should have been extracted")
	}

	// Evil file should NOT escape
	evilPath := filepath.Join(tmpDir, "evil.txt")
	if _, err := os.Stat(evilPath); !os.IsNotExist(err) {
		t.Error("tar slip: evil.txt escaped to parent directory")
	}

	if !strings.Contains(result.Output, "path traversal") {
		t.Logf("output: %s", result.Output)
	}
}

func TestTarGzExtractSymlinkSkipped(t *testing.T) {
	tmpDir := t.TempDir()
	archivePath := filepath.Join(tmpDir, "symlink.tar.gz")

	f, _ := os.Create(archivePath)
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)

	// Regular file
	content := []byte("regular")
	tw.WriteHeader(&tar.Header{Name: "regular.txt", Size: int64(len(content)), Mode: 0644})
	tw.Write(content)

	// Symlink
	tw.WriteHeader(&tar.Header{Name: "link.txt", Typeflag: tar.TypeSymlink, Linkname: "/etc/shadow", Mode: 0777})

	tw.Close()
	gz.Close()
	f.Close()

	outputDir := filepath.Join(tmpDir, "output")

	cmd := &CompressCommand{}
	params := CompressParams{Action: "extract", Path: archivePath, Output: outputDir}
	data, _ := json.Marshal(params)
	result := cmd.Execute(structs.Task{Params: string(data)})

	if result.Status != "success" {
		t.Fatalf("expected success, got: %s", result.Output)
	}
	if !strings.Contains(result.Output, "Extracted 1 files") {
		t.Errorf("expected 1 file extracted, got: %s", result.Output)
	}
	if !strings.Contains(result.Output, "symlink") {
		t.Errorf("expected symlink skip message, got: %s", result.Output)
	}
}

func TestTarGzRoundTrip(t *testing.T) {
	tmpDir := t.TempDir()
	srcDir := filepath.Join(tmpDir, "src")
	os.MkdirAll(filepath.Join(srcDir, "sub"), 0755)

	os.WriteFile(filepath.Join(srcDir, "a.txt"), []byte("alpha"), 0644)
	os.WriteFile(filepath.Join(srcDir, "sub", "b.txt"), []byte("beta"), 0644)

	archivePath := filepath.Join(tmpDir, "roundtrip.tar.gz")
	extractDir := filepath.Join(tmpDir, "out")

	cmd := &CompressCommand{}

	// Create
	createParams := CompressParams{Action: "create", Path: srcDir, Output: archivePath, Format: formatTarGz}
	data, _ := json.Marshal(createParams)
	result := cmd.Execute(structs.Task{Params: string(data)})
	if result.Status != "success" {
		t.Fatalf("create failed: %s", result.Output)
	}

	// Extract
	extractParams := CompressParams{Action: "extract", Path: archivePath, Output: extractDir}
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

func TestTarGzAutoDetectFormat(t *testing.T) {
	// Verify that .tar.gz and .tgz extensions auto-detect
	tests := []struct {
		path   string
		expect string
	}{
		{"archive.tar.gz", formatTarGz},
		{"archive.tgz", formatTarGz},
		{"archive.TaR.GZ", formatTarGz},
		{"archive.zip", formatZip},
		{"archive.dat", formatZip},
		{"", formatZip},
	}

	for _, tt := range tests {
		params := CompressParams{Path: tt.path}
		got := detectFormat(params)
		if got != tt.expect {
			t.Errorf("detectFormat(%q) = %q, want %q", tt.path, got, tt.expect)
		}
	}
}

func TestTarGzAutoDetectOverriddenByFormat(t *testing.T) {
	// Explicit format should override file extension detection
	params := CompressParams{Path: "archive.zip", Format: formatTarGz}
	got := detectFormat(params)
	if got != formatTarGz {
		t.Errorf("expected tar.gz when explicitly set, got %q", got)
	}
}

func TestTarGzAutoOutputPath(t *testing.T) {
	tmpDir := t.TempDir()
	srcDir := filepath.Join(tmpDir, "mydata")
	os.MkdirAll(srcDir, 0755)
	os.WriteFile(filepath.Join(srcDir, "test.txt"), []byte("data"), 0644)

	cmd := &CompressCommand{}
	params := CompressParams{Action: "create", Path: srcDir, Format: formatTarGz}
	data, _ := json.Marshal(params)
	result := cmd.Execute(structs.Task{Params: string(data)})

	if result.Status != "success" {
		t.Fatalf("expected success, got: %s", result.Output)
	}
	if !strings.Contains(result.Output, "mydata.tar.gz") {
		t.Errorf("expected auto-generated path with mydata.tar.gz, got: %s", result.Output)
	}
}

func TestTarGzExtractAutoOutputPath(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a tar.gz
	archivePath := filepath.Join(tmpDir, "archive.tar.gz")
	f, _ := os.Create(archivePath)
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	content := []byte("auto")
	tw.WriteHeader(&tar.Header{Name: "auto.txt", Size: int64(len(content)), Mode: 0644})
	tw.Write(content)
	tw.Close()
	gz.Close()
	f.Close()

	// Extract without specifying output — should strip .tar.gz
	cmd := &CompressCommand{}
	params := CompressParams{Action: "extract", Path: archivePath}
	data, _ := json.Marshal(params)
	result := cmd.Execute(structs.Task{Params: string(data)})

	if result.Status != "success" {
		t.Fatalf("expected success, got: %s", result.Output)
	}

	expectedOutput := filepath.Join(tmpDir, "archive")
	c, err := os.ReadFile(filepath.Join(expectedOutput, "auto.txt"))
	if err != nil || string(c) != "auto" {
		t.Errorf("auto output path extraction failed: %v", err)
	}
}

func TestTarGzExtractTgzAutoOutputPath(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a .tgz
	archivePath := filepath.Join(tmpDir, "archive.tgz")
	f, _ := os.Create(archivePath)
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	content := []byte("tgz")
	tw.WriteHeader(&tar.Header{Name: "tgz.txt", Size: int64(len(content)), Mode: 0644})
	tw.Write(content)
	tw.Close()
	gz.Close()
	f.Close()

	cmd := &CompressCommand{}
	params := CompressParams{Action: "extract", Path: archivePath}
	data, _ := json.Marshal(params)
	result := cmd.Execute(structs.Task{Params: string(data)})

	if result.Status != "success" {
		t.Fatalf("expected success, got: %s", result.Output)
	}

	expectedOutput := filepath.Join(tmpDir, "archive")
	c, err := os.ReadFile(filepath.Join(expectedOutput, "tgz.txt"))
	if err != nil || string(c) != "tgz" {
		t.Errorf("tgz auto output path extraction failed: %v", err)
	}
}

func TestTarGzMaxDepth(t *testing.T) {
	tmpDir := t.TempDir()
	srcDir := filepath.Join(tmpDir, "deep")
	deep := filepath.Join(srcDir, "a", "b", "c", "d")
	os.MkdirAll(deep, 0755)
	os.WriteFile(filepath.Join(srcDir, "top.txt"), []byte("top"), 0644)
	os.WriteFile(filepath.Join(srcDir, "a", "level1.txt"), []byte("l1"), 0644)
	os.WriteFile(filepath.Join(deep, "deep.txt"), []byte("deep"), 0644)

	outputPath := filepath.Join(tmpDir, "shallow.tar.gz")

	cmd := &CompressCommand{}
	params := CompressParams{Action: "create", Path: srcDir, Output: outputPath, Format: formatTarGz, MaxDepth: 2}
	data, _ := json.Marshal(params)
	result := cmd.Execute(structs.Task{Params: string(data)})

	if result.Status != "success" {
		t.Fatalf("expected success, got: %s", result.Output)
	}
	if !strings.Contains(result.Output, "Files: 2") {
		t.Errorf("expected 2 files (top + level1), got: %s", result.Output)
	}
}
