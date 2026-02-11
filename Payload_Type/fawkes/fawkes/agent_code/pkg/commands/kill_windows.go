//go:build windows
// +build windows

package commands

import (
	"encoding/json"
	"fmt"

	"fawkes/pkg/structs"

	"golang.org/x/sys/windows"
)

// KillCommand implements the kill command on Windows
// Uses OpenProcess + TerminateProcess for proper access control and better error messages
type KillCommand struct{}

func (c *KillCommand) Name() string {
	return "kill"
}

func (c *KillCommand) Description() string {
	return "Terminate a process by PID"
}

func (c *KillCommand) Execute(task structs.Task) structs.CommandResult {
	var params KillParams
	if err := json.Unmarshal([]byte(task.Params), &params); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error parsing parameters: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	pid := params.PID
	if pid <= 0 {
		return structs.CommandResult{
			Output:    "Error: PID must be greater than 0",
			Status:    "error",
			Completed: true,
		}
	}

	// Get process name before killing (best effort)
	procName := getProcessName(uint32(pid))

	// Open process with TERMINATE and QUERY_INFORMATION access
	handle, err := windows.OpenProcess(
		windows.PROCESS_TERMINATE|windows.PROCESS_QUERY_INFORMATION,
		false,
		uint32(pid),
	)
	if err != nil {
		// If QUERY_INFORMATION fails, try with just TERMINATE
		handle, err = windows.OpenProcess(
			windows.PROCESS_TERMINATE,
			false,
			uint32(pid),
		)
		if err != nil {
			return structs.CommandResult{
				Output:    fmt.Sprintf("Error opening process %d: %v (access denied or process does not exist)", pid, err),
				Status:    "error",
				Completed: true,
			}
		}
	}
	defer windows.CloseHandle(handle)

	// Terminate the process with exit code 1
	err = windows.TerminateProcess(handle, 1)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error terminating process %d: %v", pid, err),
			Status:    "error",
			Completed: true,
		}
	}

	if procName != "" {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Successfully terminated process %d (%s)", pid, procName),
			Status:    "completed",
			Completed: true,
		}
	}

	return structs.CommandResult{
		Output:    fmt.Sprintf("Successfully terminated process %d", pid),
		Status:    "completed",
		Completed: true,
	}
}

// getProcessName retrieves the process executable name by PID
func getProcessName(pid uint32) string {
	handle, err := windows.OpenProcess(
		windows.PROCESS_QUERY_LIMITED_INFORMATION,
		false,
		pid,
	)
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(handle)

	var buf [windows.MAX_PATH]uint16
	size := uint32(len(buf))
	err = windows.QueryFullProcessImageName(handle, 0, &buf[0], &size)
	if err != nil {
		return ""
	}

	fullPath := windows.UTF16ToString(buf[:size])
	// Extract just the filename
	for i := len(fullPath) - 1; i >= 0; i-- {
		if fullPath[i] == '\\' || fullPath[i] == '/' {
			return fullPath[i+1:]
		}
	}
	return fullPath
}
