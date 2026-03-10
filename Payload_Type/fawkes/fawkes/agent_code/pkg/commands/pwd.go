package commands

import (
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
		return errorf("Error getting current directory: %v", err)
	}

	return successResult(currentDir)
}
