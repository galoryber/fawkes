package commands

import (
	"fmt"
	"os"

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

	// Create directory with parent directories if needed (0755 permissions)
	err := os.MkdirAll(task.Params, 0755)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error creating directory: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	return structs.CommandResult{
		Output:    fmt.Sprintf("Successfully created directory: %s", task.Params),
		Status:    "success",
		Completed: true,
	}
}
