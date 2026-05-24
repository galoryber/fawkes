package files

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCompressFileGzip_SmallFile(t *testing.T) {
	// Create a small test file with compressible data
	dir := t.TempDir()
	srcPath := filepath.Join(dir, "test.txt")
	data := strings.Repeat("Hello, World! This is compressible text data. ", 100)
	if err := os.WriteFile(srcPath, []byte(data), 0644); err != nil {
		t.Fatal(err)
	}

	result, err := CompressFileGzip(srcPath)
	if err != nil {
		t.Fatalf("CompressFileGzip failed: %v", err)
	}
	defer os.Remove(result.CompressedPath)

	if result.OriginalSize != int64(len(data)) {
		t.Errorf("OriginalSize = %d, want %d", result.OriginalSize, len(data))
	}
	if result.CompressedSize >= result.OriginalSize {
		t.Errorf("CompressedSize (%d) should be < OriginalSize (%d) for compressible data",
			result.CompressedSize, result.OriginalSize)
	}
	if result.SHA256 == "" {
		t.Error("SHA256 should not be empty")
	}

	// Verify the SHA256 matches manual hash
	hasher := sha256.New()
	hasher.Write([]byte(data))
	expectedHash := hex.EncodeToString(hasher.Sum(nil))
	if result.SHA256 != expectedHash {
		t.Errorf("SHA256 = %s, want %s", result.SHA256, expectedHash)
	}

	// Verify the compressed file is valid gzip
	gzFile, err := os.Open(result.CompressedPath)
	if err != nil {
		t.Fatal(err)
	}
	defer gzFile.Close()

	gr, err := gzip.NewReader(gzFile)
	if err != nil {
		t.Fatalf("Invalid gzip: %v", err)
	}
	defer gr.Close()
}

func TestCompressFileGzip_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	srcPath := filepath.Join(dir, "empty.txt")
	if err := os.WriteFile(srcPath, []byte{}, 0644); err != nil {
		t.Fatal(err)
	}

	result, err := CompressFileGzip(srcPath)
	if err != nil {
		t.Fatalf("CompressFileGzip failed: %v", err)
	}
	defer os.Remove(result.CompressedPath)

	if result.OriginalSize != 0 {
		t.Errorf("OriginalSize = %d, want 0", result.OriginalSize)
	}
	// Gzip header adds overhead even for empty files
	if result.CompressedSize == 0 {
		t.Error("CompressedSize should be > 0 due to gzip header")
	}
}

func TestCompressFileGzip_NonexistentFile(t *testing.T) {
	_, err := CompressFileGzip("/nonexistent/file.txt")
	if err == nil {
		t.Error("Expected error for nonexistent file")
	}
}

func TestCompressFileGzip_BinaryData(t *testing.T) {
	dir := t.TempDir()
	srcPath := filepath.Join(dir, "binary.bin")
	// Random-ish binary data (less compressible)
	data := make([]byte, 4096)
	for i := range data {
		data[i] = byte(i % 256)
	}
	if err := os.WriteFile(srcPath, data, 0644); err != nil {
		t.Fatal(err)
	}

	result, err := CompressFileGzip(srcPath)
	if err != nil {
		t.Fatalf("CompressFileGzip failed: %v", err)
	}
	defer os.Remove(result.CompressedPath)

	if result.OriginalSize != int64(len(data)) {
		t.Errorf("OriginalSize = %d, want %d", result.OriginalSize, len(data))
	}
}

func TestDecompressFileGzip_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	srcPath := filepath.Join(dir, "original.txt")
	data := "Decompression test data — round trip verification."
	if err := os.WriteFile(srcPath, []byte(data), 0644); err != nil {
		t.Fatal(err)
	}

	// Compress
	result, err := CompressFileGzip(srcPath)
	if err != nil {
		t.Fatalf("Compress failed: %v", err)
	}
	defer os.Remove(result.CompressedPath)

	// Decompress
	destPath := filepath.Join(dir, "decompressed.txt")
	hash, written, err := DecompressFileGzip(result.CompressedPath, destPath)
	if err != nil {
		t.Fatalf("Decompress failed: %v", err)
	}

	if written != int64(len(data)) {
		t.Errorf("Decompressed %d bytes, want %d", written, len(data))
	}

	// Verify content matches
	decompData, err := os.ReadFile(destPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(decompData) != data {
		t.Error("Decompressed content does not match original")
	}

	// Verify hash matches the original hash
	if hash != result.SHA256 {
		t.Errorf("Decompressed hash (%s) != original hash (%s)", hash, result.SHA256)
	}
}

func TestDecompressFileGzip_InvalidFile(t *testing.T) {
	dir := t.TempDir()
	notGzPath := filepath.Join(dir, "notgz.txt")
	if err := os.WriteFile(notGzPath, []byte("not gzip data"), 0644); err != nil {
		t.Fatal(err)
	}

	destPath := filepath.Join(dir, "dest.txt")
	_, _, err := DecompressFileGzip(notGzPath, destPath)
	if err == nil {
		t.Error("Expected error for non-gzip file")
	}
}

func TestDecompressFileGzip_NonexistentFile(t *testing.T) {
	_, _, err := DecompressFileGzip("/nonexistent.gz", "/tmp/dest.txt")
	if err == nil {
		t.Error("Expected error for nonexistent file")
	}
}

func TestHashFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hashme.txt")
	data := "hash this content"
	if err := os.WriteFile(path, []byte(data), 0644); err != nil {
		t.Fatal(err)
	}

	hash, err := HashFile(path)
	if err != nil {
		t.Fatalf("HashFile failed: %v", err)
	}

	hasher := sha256.New()
	hasher.Write([]byte(data))
	expected := hex.EncodeToString(hasher.Sum(nil))
	if hash != expected {
		t.Errorf("HashFile = %s, want %s", hash, expected)
	}
}

func TestHashFile_Nonexistent(t *testing.T) {
	_, err := HashFile("/nonexistent/file.txt")
	if err == nil {
		t.Error("Expected error for nonexistent file")
	}
}

func TestIsGzipData(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want bool
	}{
		{"gzip magic bytes", []byte{0x1f, 0x8b, 0x08}, true},
		{"just magic bytes", []byte{0x1f, 0x8b}, true},
		{"not gzip", []byte{0x50, 0x4b, 0x03, 0x04}, false}, // ZIP
		{"empty", []byte{}, false},
		{"single byte", []byte{0x1f}, false},
		{"plain text", []byte("Hello"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsGzipData(tt.data); got != tt.want {
				t.Errorf("IsGzipData(%v) = %v, want %v", tt.data, got, tt.want)
			}
		})
	}
}

func TestCompressionRatio(t *testing.T) {
	tests := []struct {
		name       string
		original   int64
		compressed int64
		wantRatio  float64
	}{
		{"50% reduction", 1000, 500, 50.0},
		{"90% reduction", 1000, 100, 90.0},
		{"no reduction", 1000, 1000, 0.0},
		{"zero original", 0, 0, 0.0},
		{"slight expansion", 100, 120, -20.0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CompressionRatio(tt.original, tt.compressed)
			if got != tt.wantRatio {
				t.Errorf("CompressionRatio(%d, %d) = %.1f, want %.1f",
					tt.original, tt.compressed, got, tt.wantRatio)
			}
		})
	}
}

func TestDecompressGzipData(t *testing.T) {
	// Create gzip-compressed data
	original := []byte("Test data for in-memory decompression")
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	gw.Write(original)
	gw.Close()

	decompressed, hash, err := DecompressGzipData(buf.Bytes())
	if err != nil {
		t.Fatalf("DecompressGzipData failed: %v", err)
	}

	if !bytes.Equal(decompressed, original) {
		t.Error("Decompressed data does not match original")
	}

	hasher := sha256.New()
	hasher.Write(original)
	expectedHash := hex.EncodeToString(hasher.Sum(nil))
	if hash != expectedHash {
		t.Errorf("Hash = %s, want %s", hash, expectedHash)
	}
}

func TestDecompressGzipData_InvalidData(t *testing.T) {
	_, _, err := DecompressGzipData([]byte("not gzip data"))
	if err == nil {
		t.Error("Expected error for invalid gzip data")
	}
}
