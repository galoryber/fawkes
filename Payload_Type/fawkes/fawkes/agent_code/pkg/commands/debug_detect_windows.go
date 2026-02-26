//go:build windows

package commands

import (
	"fmt"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	kernel32DbgDetect                     = windows.NewLazySystemDLL("kernel32.dll")
	ntdllDbgDetect                        = windows.NewLazySystemDLL("ntdll.dll")
	procIsDebuggerPresent                 = kernel32DbgDetect.NewProc("IsDebuggerPresent")
	procCheckRemoteDebuggerPresent        = kernel32DbgDetect.NewProc("CheckRemoteDebuggerPresent")
	procNtQueryInformationProcessDbg      = ntdllDbgDetect.NewProc("NtQueryInformationProcess")
)

const (
	processDebugPort         = 7  // Returns debug port (non-zero = debugged)
	processDebugObjectHandle = 30 // Returns debug object handle
)

// runPlatformDebugChecks runs Windows-specific anti-debug checks.
func runPlatformDebugChecks() []debugCheck {
	var checks []debugCheck

	checks = append(checks, checkIsDebuggerPresent())
	checks = append(checks, checkRemoteDebugger())
	checks = append(checks, checkDebugPort())
	checks = append(checks, checkDebugObjectHandle())
	checks = append(checks, checkPEBBeingDebugged())
	checks = append(checks, checkHardwareBreakpoints())

	return checks
}

// checkIsDebuggerPresent calls kernel32.IsDebuggerPresent.
func checkIsDebuggerPresent() debugCheck {
	r, _, _ := procIsDebuggerPresent.Call()
	if r != 0 {
		return debugCheck{Name: "IsDebuggerPresent", Status: "DETECTED", Details: "User-mode debugger attached"}
	}
	return debugCheck{Name: "IsDebuggerPresent", Status: "CLEAN", Details: "Not detected"}
}

// checkRemoteDebugger calls kernel32.CheckRemoteDebuggerPresent.
func checkRemoteDebugger() debugCheck {
	var debuggerPresent int32
	handle, _ := windows.GetCurrentProcess()
	r, _, err := procCheckRemoteDebuggerPresent.Call(
		uintptr(handle),
		uintptr(unsafe.Pointer(&debuggerPresent)),
	)
	if r == 0 {
		return debugCheck{Name: "CheckRemoteDebuggerPresent", Status: "ERROR", Details: fmt.Sprintf("API failed: %v", err)}
	}
	if debuggerPresent != 0 {
		return debugCheck{Name: "CheckRemoteDebuggerPresent", Status: "DETECTED", Details: "Remote debugger attached"}
	}
	return debugCheck{Name: "CheckRemoteDebuggerPresent", Status: "CLEAN", Details: "Not detected"}
}

// checkDebugPort uses NtQueryInformationProcess with ProcessDebugPort.
func checkDebugPort() debugCheck {
	handle, _ := windows.GetCurrentProcess()
	var debugPort uintptr
	var returnLen uint32
	r, _, _ := procNtQueryInformationProcessDbg.Call(
		uintptr(handle),
		uintptr(processDebugPort),
		uintptr(unsafe.Pointer(&debugPort)),
		uintptr(unsafe.Sizeof(debugPort)),
		uintptr(unsafe.Pointer(&returnLen)),
	)
	if r != 0 {
		return debugCheck{Name: "NtQuery (DebugPort)", Status: "ERROR", Details: fmt.Sprintf("NTSTATUS: 0x%X", r)}
	}
	if debugPort != 0 {
		return debugCheck{Name: "NtQuery (DebugPort)", Status: "DETECTED", Details: fmt.Sprintf("Debug port: 0x%X", debugPort)}
	}
	return debugCheck{Name: "NtQuery (DebugPort)", Status: "CLEAN", Details: "Debug port: 0"}
}

// checkDebugObjectHandle uses NtQueryInformationProcess with ProcessDebugObjectHandle.
func checkDebugObjectHandle() debugCheck {
	handle, _ := windows.GetCurrentProcess()
	var debugHandle uintptr
	var returnLen uint32
	r, _, _ := procNtQueryInformationProcessDbg.Call(
		uintptr(handle),
		uintptr(processDebugObjectHandle),
		uintptr(unsafe.Pointer(&debugHandle)),
		uintptr(unsafe.Sizeof(debugHandle)),
		uintptr(unsafe.Pointer(&returnLen)),
	)
	// STATUS_PORT_NOT_SET (0xC0000353) means no debugger — expected when clean
	if r == 0xC0000353 {
		return debugCheck{Name: "NtQuery (DebugObjectHandle)", Status: "CLEAN", Details: "No debug object"}
	}
	if r != 0 {
		return debugCheck{Name: "NtQuery (DebugObjectHandle)", Status: "CLEAN", Details: "No debug object"}
	}
	if debugHandle != 0 {
		return debugCheck{Name: "NtQuery (DebugObjectHandle)", Status: "DETECTED", Details: fmt.Sprintf("Debug object handle: 0x%X", debugHandle)}
	}
	return debugCheck{Name: "NtQuery (DebugObjectHandle)", Status: "CLEAN", Details: "No debug object"}
}

// checkPEBBeingDebugged reads the PEB.BeingDebugged byte.
func checkPEBBeingDebugged() debugCheck {
	handle, _ := windows.GetCurrentProcess()
	var pbi PROCESS_BASIC_INFORMATION
	var returnLen uint32
	r, _, _ := procNtQueryInformationProcessDbg.Call(
		uintptr(handle),
		0, // ProcessBasicInformation
		uintptr(unsafe.Pointer(&pbi)),
		uintptr(unsafe.Sizeof(pbi)),
		uintptr(unsafe.Pointer(&returnLen)),
	)
	if r != 0 {
		return debugCheck{Name: "PEB.BeingDebugged", Status: "ERROR", Details: fmt.Sprintf("NTSTATUS: 0x%X", r)}
	}
	// PEB.BeingDebugged is at offset 0x2 from PEB base (BYTE)
	beingDebugged := *(*byte)(unsafe.Pointer(pbi.PebBaseAddress + 0x2))
	if beingDebugged != 0 {
		return debugCheck{Name: "PEB.BeingDebugged", Status: "DETECTED", Details: fmt.Sprintf("Flag: %d", beingDebugged)}
	}
	return debugCheck{Name: "PEB.BeingDebugged", Status: "CLEAN", Details: "Flag: 0"}
}

// checkHardwareBreakpoints reads DR0-DR3 via GetThreadContext to detect analyst-set breakpoints.
// Uses CONTEXT_AMD64 and procGetThreadContext from hwbp.go (same package).
func checkHardwareBreakpoints() debugCheck {
	var ctx CONTEXT_AMD64
	ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS

	thread, _ := windows.GetCurrentThread()
	ret, _, err := procGetThreadContext.Call(uintptr(thread), uintptr(unsafe.Pointer(&ctx)))
	if ret == 0 {
		return debugCheck{Name: "Hardware Breakpoints (DR0-3)", Status: "ERROR", Details: fmt.Sprintf("GetThreadContext: %v", err)}
	}

	drSet := 0
	var details []string
	if ctx.Dr0 != 0 {
		drSet++
		details = append(details, fmt.Sprintf("Dr0=0x%X", ctx.Dr0))
	}
	if ctx.Dr1 != 0 {
		drSet++
		details = append(details, fmt.Sprintf("Dr1=0x%X", ctx.Dr1))
	}
	if ctx.Dr2 != 0 {
		drSet++
		details = append(details, fmt.Sprintf("Dr2=0x%X", ctx.Dr2))
	}
	if ctx.Dr3 != 0 {
		drSet++
		details = append(details, fmt.Sprintf("Dr3=0x%X", ctx.Dr3))
	}

	if drSet > 0 {
		return debugCheck{
			Name:    "Hardware Breakpoints (DR0-3)",
			Status:  "WARNING",
			Details: fmt.Sprintf("%d register(s) set: %s", drSet, strings.Join(details, ", ")),
		}
	}
	return debugCheck{Name: "Hardware Breakpoints (DR0-3)", Status: "CLEAN", Details: "All DR registers clear"}
}
