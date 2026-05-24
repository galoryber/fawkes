//go:build windows
// +build windows

package commands

import (
	"fmt"
	"syscall"
	"unsafe"

	"fawkes/pkg/structs"

	"golang.org/x/sys/windows"
)

// SuspendCommand suspends or resumes a process by PID using NtSuspendProcess/NtResumeProcess.
type SuspendCommand struct{}

func (c *SuspendCommand) Name() string        { return "suspend" }
func (c *SuspendCommand) Description() string { return "Suspend or resume a process by PID" }

var (
	ntdllSuspend          = windows.NewLazySystemDLL("ntdll.dll")
	procNtSuspendProcess  = ntdllSuspend.NewProc("NtSuspendProcess")
	procNtResumeProcess   = ntdllSuspend.NewProc("NtResumeProcess")
	suspendKernel32       = windows.NewLazySystemDLL("kernel32.dll")
	suspendQueryImageName = suspendKernel32.NewProc("QueryFullProcessImageNameW")
)

func (c *SuspendCommand) Execute(task structs.Task) structs.CommandResult {
	params, parseErr := unmarshalParams[SuspendParams](task)
	if parseErr != nil {
		return *parseErr
	}

	if params.PID <= 0 {
		return errorResult("Error: PID must be greater than 0")
	}

	if params.Action == "" {
		params.Action = "suspend"
	}

	// Open the target process
	hProcess, err := windows.OpenProcess(windows.PROCESS_SUSPEND_RESUME, false, uint32(params.PID))
	if err != nil {
		return errorf("Failed to open process %d: %v", params.PID, err)
	}
	defer windows.CloseHandle(hProcess)

	procName := suspendGetProcessName(uint32(params.PID))

	switch params.Action {
	case "suspend":
		status, _, _ := procNtSuspendProcess.Call(uintptr(hProcess))
		if status != 0 {
			return errorf("NtSuspendProcess failed for PID %d: NTSTATUS 0x%X", params.PID, status)
		}
		name := ""
		if procName != "" {
			name = fmt.Sprintf(" (%s)", procName)
		}
		return successf("Process %d%s suspended. Use 'suspend -action resume -pid %d' to resume.", params.PID, name, params.PID)

	case "resume":
		status, _, _ := procNtResumeProcess.Call(uintptr(hProcess))
		if status != 0 {
			return errorf("NtResumeProcess failed for PID %d: NTSTATUS 0x%X", params.PID, status)
		}
		name := ""
		if procName != "" {
			name = fmt.Sprintf(" (%s)", procName)
		}
		return successf("Process %d%s resumed.", params.PID, name)

	default:
		return errorf("Unknown action: %s. Use: suspend, resume", params.Action)
	}
}

// suspendGetProcessName resolves PID to executable name
func suspendGetProcessName(pid uint32) string {
	h, err := windows.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(h)

	var buf [syscall.MAX_PATH]uint16
	size := uint32(len(buf))
	ret, _, _ := suspendQueryImageName.Call(
		uintptr(h),
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
