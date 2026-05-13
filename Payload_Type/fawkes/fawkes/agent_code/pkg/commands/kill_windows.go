//go:build windows
// +build windows

package commands

import (
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
	params, parseErr := unmarshalParams[KillParams](task)
	if parseErr != nil {
		return *parseErr
	}

	pid := params.PID
	if pid <= 0 {
		return errorResult("Error: PID must be greater than 0")
	}

	// Get process name before killing (best effort)
	procName := killGetProcessName(uint32(pid))

	// Open the target process directly with PROCESS_TERMINATE rights and
	// call TerminateProcess. Going through os.FindProcess + proc.Kill()
	// opened the handle with limited rights (PROCESS_QUERY_INFORMATION +
	// SYNCHRONIZE) and then tried to DuplicateHandle to upgrade to
	// PROCESS_TERMINATE — which fails with ACCESS_DENIED on processes the
	// caller can normally terminate, including its own-user processes when
	// the original limited handle's ACL doesn't permit the upgrade. Caught
	// by the Wave 1 reliability sweep where a high-integrity admin agent
	// (with SeDebugPrivilege) couldn't kill a SYSTEM-owned ping process.
	handle, err := windows.OpenProcess(windows.PROCESS_TERMINATE, false, uint32(pid))
	if err != nil {
		return errorf("Error opening process %d: %v", pid, err)
	}
	defer windows.CloseHandle(handle)

	if err := windows.TerminateProcess(handle, 1); err != nil {
		return errorf("Error killing process %d: %v", pid, err)
	}

	if procName != "" {
		return successf("Successfully terminated process %d (%s)", pid, procName)
	}

	return successf("Successfully terminated process %d", pid)
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
