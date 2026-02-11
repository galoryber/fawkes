//go:build windows
// +build windows

package commands

import (
	"encoding/json"
	"fmt"
	"syscall"
	"unsafe"

	"fawkes/pkg/structs"

	"golang.org/x/sys/windows"
)

const (
	killProcessTerminate            = 0x0001
	killProcessQueryInformation     = 0x0400
	killProcessQueryLimitedInfo     = 0x1000
)

var (
	killKernel32           = windows.NewLazySystemDLL("kernel32.dll")
	killOpenProcess        = killKernel32.NewProc("OpenProcess")
	killTerminateProcess   = killKernel32.NewProc("TerminateProcess")
	killCloseHandle        = killKernel32.NewProc("CloseHandle")
	killQueryFullProcessImageNameW = killKernel32.NewProc("QueryFullProcessImageNameW")
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
	procName := killGetProcessName(uint32(pid))

	// Open process with TERMINATE + QUERY access
	handle, _, err := killOpenProcess.Call(
		uintptr(killProcessTerminate|killProcessQueryInformation),
		0, // bInheritHandle = FALSE
		uintptr(pid),
	)
	if handle == 0 {
		// Try with just TERMINATE
		handle, _, err = killOpenProcess.Call(
			uintptr(killProcessTerminate),
			0,
			uintptr(pid),
		)
		if handle == 0 {
			return structs.CommandResult{
				Output:    fmt.Sprintf("Error opening process %d: %v", pid, err),
				Status:    "error",
				Completed: true,
			}
		}
	}
	defer killCloseHandle.Call(handle)

	// Terminate the process with exit code 1
	ret, _, err := killTerminateProcess.Call(handle, 1)
	if ret == 0 {
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

// killGetProcessName retrieves the process executable name by PID
func killGetProcessName(pid uint32) string {
	handle, _, _ := killOpenProcess.Call(
		uintptr(killProcessQueryLimitedInfo),
		0,
		uintptr(pid),
	)
	if handle == 0 {
		return ""
	}
	defer killCloseHandle.Call(handle)

	var buf [syscall.MAX_PATH]uint16
	size := uint32(len(buf))
	ret, _, _ := killQueryFullProcessImageNameW.Call(
		handle,
		0,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
	)
	if ret == 0 {
		return ""
	}

	fullPath := syscall.UTF16ToString(buf[:size])
	// Extract just the filename
	for i := len(fullPath) - 1; i >= 0; i-- {
		if fullPath[i] == '\\' || fullPath[i] == '/' {
			return fullPath[i+1:]
		}
	}
	return fullPath
}
