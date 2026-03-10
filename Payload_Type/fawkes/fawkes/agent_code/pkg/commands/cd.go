package commands

import (
	"encoding/json"
	"os"

	"fawkes/pkg/structs"
)

// CdCommand implements the cd command
type CdCommand struct{}

// Name returns the command name
func (c *CdCommand) Name() string {
	return "cd"
}

// Description returns the command description
func (c *CdCommand) Description() string {
	return "Change directory - changes the current working directory"
}

// Execute executes the cd command
func (c *CdCommand) Execute(task structs.Task) structs.CommandResult {
	// Parse parameters
	var args struct {
		Path string `json:"path"`
	}

	// Check if parameters are provided
	if task.Params == "" {
		return errorResult("Error: No directory path specified")
	}

	// Try to parse as JSON first
	if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
		// If not JSON, treat as simple string path
		args.Path = task.Params
	}

	// Strip surrounding quotes in case the user wrapped the path (e.g. "C:\Program Data")
	args.Path = stripPathQuotes(args.Path)

	// Ensure we have a path
	if args.Path == "" {
		return errorResult("Error: No directory path specified")
	}

	// Change directory
	if err := os.Chdir(args.Path); err != nil {
		return errorf("Error changing directory: %v", err)
	}

	// Get the new current directory to confirm the change
	newDir, err := os.Getwd()
	if err != nil {
		return successf("Changed directory but failed to get new path: %v", err)
	}

	return successf("Changed directory to: %s", newDir)
}
