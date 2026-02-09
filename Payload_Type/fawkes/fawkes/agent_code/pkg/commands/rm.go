package commands

import (
	"fmt"
	"os"
	"strings"

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

	// Strip surrounding quotes in case the user wrapped the path (e.g. "C:\Program Data")
	path := strings.TrimSpace(task.Params)
	if len(path) >= 2 {
		if (path[0] == '"' && path[len(path)-1] == '"') ||
			(path[0] == '\'' && path[len(path)-1] == '\'') {
			path = path[1 : len(path)-1]
		}
	}

	// Check if path exists
	fileInfo, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return structs.CommandResult{
				Output:    fmt.Sprintf("Error: Path does not exist: %s", path),
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
	err = os.RemoveAll(path)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error removing %s: %v", itemType, err),
			Status:    "error",
			Completed: true,
		}
	}

	return structs.CommandResult{
		Output:    fmt.Sprintf("Successfully removed %s: %s", itemType, path),
		Status:    "success",
		Completed: true,
	}
}
