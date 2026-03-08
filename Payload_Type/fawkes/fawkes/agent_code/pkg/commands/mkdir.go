package commands

import (
	"encoding/json"
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
		return errorResult("Error: No directory path provided")
	}

	// Try to parse as JSON first (Mythic API sends JSON parameters)
	var args struct {
		Path string `json:"path"`
	}
	path := task.Params
	if err := json.Unmarshal([]byte(task.Params), &args); err == nil && args.Path != "" {
		path = args.Path
	}

	// Strip surrounding quotes in case the user wrapped the path (e.g. "C:\Program Data")
	path = stripPathQuotes(path)

	// Create directory with parent directories if needed (0755 permissions)
	err := os.MkdirAll(path, 0755)
	if err != nil {
		return errorf("Error creating directory: %v", err)
	}

	return successf("Successfully created directory: %s", path)
}
