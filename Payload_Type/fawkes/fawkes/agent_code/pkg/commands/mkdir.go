package commands

import (
	"encoding/json"
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
		return errorResult("Error: No directory path provided")
	}

	path, err := resolveMkdirPath(task.Params)
	if err != nil {
		return errorf("Error: %v", err)
	}

	// Strip surrounding quotes in case the user wrapped the path (e.g. "C:\Program Data")
	path = stripPathQuotes(path)

	// Create directory with parent directories if needed (0755 permissions)
	if err := os.MkdirAll(path, 0755); err != nil {
		return errorf("Error creating directory: %v", err)
	}

	return successf("Successfully created directory: %s", path)
}

// resolveMkdirPath extracts the directory path from task params. Accepts a
// plain string, or JSON with a "path", "directory", or "full_path" key.
// If the input parses as a JSON object but has none of those keys, returns
// an error rather than silently treating the raw JSON as a literal path
// (which produced a directory named like the JSON blob on filesystems that
// accept the characters — observed on Linux during reliability sweeps).
func resolveMkdirPath(params string) (string, error) {
	var obj map[string]interface{}
	if err := json.Unmarshal([]byte(params), &obj); err == nil {
		if v, ok := obj["full_path"].(string); ok && v != "" {
			return v, nil
		}
		if v, ok := obj["path"].(string); ok && v != "" {
			return v, nil
		}
		if v, ok := obj["directory"].(string); ok && v != "" {
			return v, nil
		}
		return "", fmt.Errorf("JSON input had no recognized key (expected 'path', 'directory', or 'full_path')")
	}
	return params, nil
}
