package files

import (
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
)

// CompressResult holds the result of a file compression operation
type CompressResult struct {
	CompressedPath string // Path to the compressed temp file
	OriginalSize   int64  // Size of original file
	CompressedSize int64  // Size after compression
	SHA256         string // SHA256 hash of the original file
}

// CompressFileGzip compresses a file to a temporary gzip file.
// Returns the compressed temp file path and metadata.
// The caller is responsible for cleaning up the temp file.
func CompressFileGzip(srcPath string) (*CompressResult, error) {
	src, err := os.Open(srcPath)
	if err != nil {
		return nil, fmt.Errorf("open source: %w", err)
	}
	defer src.Close()

	srcInfo, err := src.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat source: %w", err)
	}

	tmpFile, err := os.CreateTemp("", "fawkes-gz-*")
	if err != nil {
		return nil, fmt.Errorf("create temp: %w", err)
	}
	tmpPath := tmpFile.Name()

	// Hash the original while compressing
	hasher := sha256.New()
	tee := io.TeeReader(src, hasher)

	gw, err := gzip.NewWriterLevel(tmpFile, gzip.BestCompression)
	if err != nil {
		tmpFile.Close()
		os.Remove(tmpPath)
		return nil, fmt.Errorf("create gzip writer: %w", err)
	}

	if _, err := io.Copy(gw, tee); err != nil {
		gw.Close()
		tmpFile.Close()
		os.Remove(tmpPath)
		return nil, fmt.Errorf("compress: %w", err)
	}

	if err := gw.Close(); err != nil {
		tmpFile.Close()
		os.Remove(tmpPath)
		return nil, fmt.Errorf("finalize gzip: %w", err)
	}

	if err := tmpFile.Close(); err != nil {
		os.Remove(tmpPath)
		return nil, fmt.Errorf("close temp: %w", err)
	}

	compInfo, err := os.Stat(tmpPath)
	if err != nil {
		os.Remove(tmpPath)
		return nil, fmt.Errorf("stat compressed: %w", err)
	}

	return &CompressResult{
		CompressedPath: tmpPath,
		OriginalSize:   srcInfo.Size(),
		CompressedSize: compInfo.Size(),
		SHA256:         hex.EncodeToString(hasher.Sum(nil)),
	}, nil
}

// DecompressFileGzip decompresses a gzip file to the destination path.
// Returns the SHA256 hash of the decompressed content and the number of bytes written.
func DecompressFileGzip(gzPath, destPath string) (hash string, written int64, err error) {
	src, err := os.Open(gzPath)
	if err != nil {
		return "", 0, fmt.Errorf("open gzip source: %w", err)
	}
	defer src.Close()

	gr, err := gzip.NewReader(src)
	if err != nil {
		return "", 0, fmt.Errorf("create gzip reader: %w", err)
	}
	defer gr.Close()

	dst, err := os.OpenFile(destPath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0700)
	if err != nil {
		return "", 0, fmt.Errorf("open dest: %w", err)
	}
	defer dst.Close()

	hasher := sha256.New()
	mw := io.MultiWriter(dst, hasher)

	written, err = io.Copy(mw, gr)
	if err != nil {
		return "", written, fmt.Errorf("decompress: %w", err)
	}

	if err := dst.Close(); err != nil {
		return "", written, fmt.Errorf("close dest: %w", err)
	}

	return hex.EncodeToString(hasher.Sum(nil)), written, nil
}

// HashFile computes the SHA256 hash of a file.
func HashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open: %w", err)
	}
	defer f.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, f); err != nil {
		return "", fmt.Errorf("hash: %w", err)
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// DecompressGzipData decompresses gzip data from a byte slice.
// Returns the decompressed data and SHA256 hash.
func DecompressGzipData(data []byte) ([]byte, string, error) {
	// Use a temp file approach to handle large data without excessive memory
	tmpGz, err := os.CreateTemp("", "fawkes-ungz-in-*")
	if err != nil {
		return nil, "", fmt.Errorf("create temp: %w", err)
	}
	tmpGzPath := tmpGz.Name()
	defer os.Remove(tmpGzPath)

	if _, err := tmpGz.Write(data); err != nil {
		tmpGz.Close()
		return nil, "", fmt.Errorf("write temp: %w", err)
	}
	tmpGz.Close()

	tmpOut, err := os.CreateTemp("", "fawkes-ungz-out-*")
	if err != nil {
		return nil, "", fmt.Errorf("create output temp: %w", err)
	}
	tmpOutPath := tmpOut.Name()
	tmpOut.Close()
	defer os.Remove(tmpOutPath)

	hash, _, err := DecompressFileGzip(tmpGzPath, tmpOutPath)
	if err != nil {
		return nil, "", err
	}

	result, err := os.ReadFile(tmpOutPath)
	if err != nil {
		return nil, "", fmt.Errorf("read decompressed: %w", err)
	}

	return result, hash, nil
}

// IsGzipData checks if data starts with the gzip magic bytes (0x1f, 0x8b).
func IsGzipData(data []byte) bool {
	return len(data) >= 2 && data[0] == 0x1f && data[1] == 0x8b
}

// CompressionRatio returns the compression ratio as a percentage saved.
// e.g., original=1000, compressed=300 returns 70.0 (70% saved).
func CompressionRatio(original, compressed int64) float64 {
	if original == 0 {
		return 0
	}
	return float64(original-compressed) / float64(original) * 100
}
