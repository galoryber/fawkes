package commands

import (
	"encoding/json"
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
		return errorResult("Error: No path provided")
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

	// Check if path exists
	fileInfo, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return errorf("Error: Path does not exist: %s", path)
		}
		return errorf("Error checking path: %v", err)
	}

	// Determine if it's a file or directory
	itemType := "file"
	if fileInfo.IsDir() {
		itemType = "directory"
	}

	// Remove the file or directory (recursively if directory)
	err = os.RemoveAll(path)
	if err != nil {
		return errorf("Error removing %s: %v", itemType, err)
	}

	return successf("Successfully removed %s: %s", itemType, path)
}
