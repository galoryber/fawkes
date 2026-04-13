package commands

import (
	"os"

	"fawkes/pkg/structs"
)

// MvCommand implements the mv command
type MvCommand struct{}

// Name returns the command name
func (c *MvCommand) Name() string {
	return "mv"
}

// Description returns the command description
func (c *MvCommand) Description() string {
	return "Move file - moves a file from source to destination"
}

type mvArgs struct {
	Source      string `json:"source"`
	Destination string `json:"destination"`
}

// Execute executes the mv command
func (c *MvCommand) Execute(task structs.Task) structs.CommandResult {
	// Check if parameters are provided
	if task.Params == "" {
		return errorResult("Error: No parameters specified. Usage: mv <source> <destination>")
	}

	args, parseErr := unmarshalParams[mvArgs](task)
	if parseErr != nil {
		return *parseErr
	}

	// Strip surrounding quotes in case the user wrapped paths (e.g. "C:\Program Data\file.txt")
	args.Source = stripPathQuotes(args.Source)
	args.Destination = stripPathQuotes(args.Destination)

	// Validate parameters
	if args.Source == "" || args.Destination == "" {
		return errorResult("Error: Both source and destination must be specified")
	}

	// Check if source file exists
	if _, err := os.Stat(args.Source); err != nil {
		return errorf("Error: Source file does not exist or cannot be accessed: %v", err)
	}

	// Move/rename the file
	if err := os.Rename(args.Source, args.Destination); err != nil {
		return errorf("Error moving file: %v", err)
	}

	return successf("Successfully moved %s to %s", args.Source, args.Destination)
}
