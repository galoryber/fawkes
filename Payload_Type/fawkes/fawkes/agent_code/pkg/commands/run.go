package commands

import (
	"fmt"
	"strings"

	"fawkes/pkg/structs"
)

// RunCommand implements the run command
type RunCommand struct{}

// Name returns the command name
func (c *RunCommand) Name() string {
	return "run"
}

// Description returns the command description
func (c *RunCommand) Description() string {
	return "Execute a command in a child process"
}

// Execute executes the run command
func (c *RunCommand) Execute(task structs.Task) structs.CommandResult {
	if task.Params == "" {
		return structs.CommandResult{
			Output:    "Error: No command specified",
			Status:    "error",
			Completed: true,
		}
	}

	// executeRunCommand is platform-specific:
	// - Windows: uses CreateProcessWithTokenW when impersonating,
	//   standard exec.Command otherwise
	// - Unix: always uses /bin/sh -c
	output, err := executeRunCommand(task.Params)

	if err != nil {
		outputStr := strings.TrimSpace(output)
		if outputStr != "" {
			return structs.CommandResult{
				Output:    fmt.Sprintf("%s\nError: %v", outputStr, err),
				Status:    "error",
				Completed: true,
			}
		}
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error executing command: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	outputStr := strings.TrimSpace(output)
	if outputStr == "" {
		outputStr = "Command executed successfully (no output)"
	}

	return structs.CommandResult{
		Output:    outputStr,
		Status:    "success",
		Completed: true,
	}
}
