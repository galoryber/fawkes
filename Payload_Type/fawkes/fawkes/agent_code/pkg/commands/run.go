package commands

import (
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
		return errorResult("Error: No command specified")
	}

	// executeRunCommand is platform-specific:
	// - Windows: uses CreateProcessWithTokenW when impersonating,
	//   standard exec.Command otherwise
	// - Unix: always uses /bin/sh -c
	output, err := executeRunCommand(task.Params)

	if err != nil {
		outputStr := strings.TrimSpace(output)
		if outputStr != "" {
			return errorf("%s\nError: %v", outputStr, err)
		}
		return errorf("Error executing command: %v", err)
	}

	outputStr := strings.TrimSpace(output)
	if outputStr == "" {
		outputStr = "Command executed successfully (no output)"
	}

	return successResult(outputStr)
}
