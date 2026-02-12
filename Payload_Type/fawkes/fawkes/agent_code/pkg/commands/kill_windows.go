//go:build windows
// +build windows

package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"syscall"
	"unsafe"

	"fawkes/pkg/structs"

	"golang.org/x/sys/windows"
)

var (
	killKernel32                   = windows.NewLazySystemDLL("kernel32.dll")
	killQueryFullProcessImageNameW = killKernel32.NewProc("QueryFullProcessImageNameW")
)

// KillCommand implements the kill command on Windows
// Uses os.FindProcess + Kill with added process name resolution
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

	proc, err := os.FindProcess(pid)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error finding process %d: %v", pid, err),
			Status:    "error",
			Completed: true,
		}
	}

	err = proc.Kill()
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error killing process %d: %v", pid, err),
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
	const PROCESS_QUERY_LIMITED_INFORMATION = 0x1000

	handle, err := windows.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(handle)

	var buf [syscall.MAX_PATH]uint16
	size := uint32(len(buf))
	ret, _, _ := killQueryFullProcessImageNameW.Call(
		uintptr(handle),
		0,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
	)
	if ret == 0 {
		return ""
	}

	fullPath := syscall.UTF16ToString(buf[:size])
	for i := len(fullPath) - 1; i >= 0; i-- {
		if fullPath[i] == '\\' || fullPath[i] == '/' {
			return fullPath[i+1:]
		}
	}
	return fullPath
}
