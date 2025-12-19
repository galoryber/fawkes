package commands

import (
	"fmt"
	"os"

	"fawkes/pkg/structs"
)

// PwdCommand implements the pwd command
type PwdCommand struct{}

// Name returns the command name
func (c *PwdCommand) Name() string {
	return "pwd"
}

// Description returns the command description
func (c *PwdCommand) Description() string {
	return "Print working directory - shows the current directory path"
}

// Execute executes the pwd command
func (c *PwdCommand) Execute(task structs.Task) structs.CommandResult {
	// Get current working directory
	currentDir, err := os.Getwd()
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error getting current directory: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	return structs.CommandResult{
		Output:    currentDir,
		Status:    "success", 
		Completed: true,
	}
}