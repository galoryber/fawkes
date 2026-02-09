package commands

import (
	"fmt"
	"os"
	"strings"

	"fawkes/pkg/structs"
)

// MkdirCommand implements the mkdir command
type MkdirCommand struct{}

// Name returns the command name
func (c *MkdirCommand) Name() string {
	return "mkdir"
}

// Description returns the command description
func (c *MkdirCommand) Description() string {
	return "Create a new directory"
}

// Execute executes the mkdir command
func (c *MkdirCommand) Execute(task structs.Task) structs.CommandResult {
	if task.Params == "" {
		return structs.CommandResult{
			Output:    "Error: No directory path provided",
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

	// Create directory with parent directories if needed (0755 permissions)
	err := os.MkdirAll(path, 0755)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error creating directory: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	return structs.CommandResult{
		Output:    fmt.Sprintf("Successfully created directory: %s", path),
		Status:    "success",
		Completed: true,
	}
}
