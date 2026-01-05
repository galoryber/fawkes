package commands

import (
	"encoding/json"
	"fmt"
	"os"

	"fawkes/pkg/structs"
)

// MvCommand implements the mv command
type MvCommand struct{}

// Name returns the command name
func (c *MvCommand) Name() string {
	return "mv"
}

// Description returns the command description
func (c *MvCommand) Description() string {
	return "Move file - moves a file from source to destination"
}

// Execute executes the mv command
func (c *MvCommand) Execute(task structs.Task) structs.CommandResult {
	// Parse parameters
	var args struct {
		Source      string `json:"source"`
		Destination string `json:"destination"`
	}

	// Check if parameters are provided
	if task.Params == "" {
		return structs.CommandResult{
			Output:    "Error: No parameters specified. Usage: mv <source> <destination>",
			Status:    "error",
			Completed: true,
		}
	}

	// Try to parse as JSON
	if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error parsing parameters: %v. Usage: mv <source> <destination>", err),
			Status:    "error",
			Completed: true,
		}
	}

	// Validate parameters
	if args.Source == "" || args.Destination == "" {
		return structs.CommandResult{
			Output:    "Error: Both source and destination must be specified",
			Status:    "error",
			Completed: true,
		}
	}

	// Check if source file exists
	if _, err := os.Stat(args.Source); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error: Source file does not exist or cannot be accessed: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	// Move/rename the file
	if err := os.Rename(args.Source, args.Destination); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error moving file: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	return structs.CommandResult{
		Output:    fmt.Sprintf("Successfully moved %s to %s", args.Source, args.Destination),
		Status:    "success",
		Completed: true,
	}
}
