package commands

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"fawkes/pkg/structs"
)

// CpCommand implements the cp command
type CpCommand struct{}

// Name returns the command name
func (c *CpCommand) Name() string {
	return "cp"
}

// Description returns the command description
func (c *CpCommand) Description() string {
	return "Copy file - copies a file from source to destination"
}

// Execute executes the cp command
func (c *CpCommand) Execute(task structs.Task) structs.CommandResult {
	// Parse parameters
	var args struct {
		Source      string `json:"source"`
		Destination string `json:"destination"`
	}

	// Check if parameters are provided
	if task.Params == "" {
		return structs.CommandResult{
			Output:    "Error: No parameters specified. Usage: cp <source> <destination>",
			Status:    "error",
			Completed: true,
		}
	}

	// Try to parse as JSON
	if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error parsing parameters: %v. Usage: cp <source> <destination>", err),
			Status:    "error",
			Completed: true,
		}
	}

	// Strip surrounding quotes in case the user wrapped paths (e.g. "C:\Program Data\file.txt")
	args.Source = stripPathQuotes(args.Source)
	args.Destination = stripPathQuotes(args.Destination)

	// Validate parameters
	if args.Source == "" || args.Destination == "" {
		return structs.CommandResult{
			Output:    "Error: Both source and destination must be specified",
			Status:    "error",
			Completed: true,
		}
	}

	// Open source file
	sourceFile, err := os.Open(args.Source)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error opening source file: %v", err),
			Status:    "error",
			Completed: true,
		}
	}
	defer sourceFile.Close()

	// Get source file info
	sourceInfo, err := sourceFile.Stat()
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error getting source file info: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	// Create destination file
	destFile, err := os.Create(args.Destination)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error creating destination file: %v", err),
			Status:    "error",
			Completed: true,
		}
	}
	defer destFile.Close()

	// Copy the file contents
	bytesCopied, err := io.Copy(destFile, sourceFile)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error copying file: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	// Set permissions on destination file to match source
	if err := os.Chmod(args.Destination, sourceInfo.Mode()); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("File copied (%d bytes) but failed to set permissions: %v", bytesCopied, err),
			Status:    "success",
			Completed: true,
		}
	}

	return structs.CommandResult{
		Output:    fmt.Sprintf("Successfully copied %d bytes from %s to %s", bytesCopied, args.Source, args.Destination),
		Status:    "success",
		Completed: true,
	}
}
