package commands

import (
	"fmt"
	"os"

	"fawkes/pkg/structs"
)

// RmCommand implements the rm command
type RmCommand struct{}

// Name returns the command name
func (c *RmCommand) Name() string {
	return "rm"
}

// Description returns the command description
func (c *RmCommand) Description() string {
	return "Remove a file or directory"
}

// Execute executes the rm command
func (c *RmCommand) Execute(task structs.Task) structs.CommandResult {
	if task.Params == "" {
		return structs.CommandResult{
			Output:    "Error: No path provided",
			Status:    "error",
			Completed: true,
		}
	}

	// Check if path exists
	fileInfo, err := os.Stat(task.Params)
	if err != nil {
		if os.IsNotExist(err) {
			return structs.CommandResult{
				Output:    fmt.Sprintf("Error: Path does not exist: %s", task.Params),
				Status:    "error",
				Completed: true,
			}
		}
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error checking path: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	// Determine if it's a file or directory
	itemType := "file"
	if fileInfo.IsDir() {
		itemType = "directory"
	}

	// Remove the file or directory (recursively if directory)
	err = os.RemoveAll(task.Params)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error removing %s: %v", itemType, err),
			Status:    "error",
			Completed: true,
		}
	}

	return structs.CommandResult{
		Output:    fmt.Sprintf("Successfully removed %s: %s", itemType, task.Params),
		Status:    "success",
		Completed: true,
	}
}
