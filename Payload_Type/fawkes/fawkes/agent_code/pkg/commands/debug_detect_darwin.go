//go:build darwin

package commands

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

// runPlatformDebugChecks runs macOS-specific anti-debug checks.
func runPlatformDebugChecks() []debugCheck {
	var checks []debugCheck

	checks = append(checks, checkSysctlPTraced())
	checks = append(checks, checkDyldInsertLibraries())

	return checks
}

// checkSysctlPTraced uses sysctl to check the P_TRACED flag on the current process.
func checkSysctlPTraced() debugCheck {
	// struct kinfo_proc lookup via sysctl
	const (
		ctlKern     = 1
		kernProc    = 14
		kernProcPID = 1
	)

	pid := os.Getpid()
	mib := [4]int32{ctlKern, kernProc, kernProcPID, int32(pid)}

	// First call to get size
	var size uintptr
	_, _, errno := syscall.Syscall6(
		syscall.SYS___SYSCTL,
		uintptr(unsafe.Pointer(&mib[0])),
		4,
		0,
		uintptr(unsafe.Pointer(&size)),
		0,
		0,
	)
	if errno != 0 {
		return debugCheck{Name: "sysctl P_TRACED", Status: "ERROR", Details: fmt.Sprintf("sysctl size query failed: %v", errno)}
	}

	// Allocate buffer and get data
	buf := make([]byte, size)
	_, _, errno = syscall.Syscall6(
		syscall.SYS___SYSCTL,
		uintptr(unsafe.Pointer(&mib[0])),
		4,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
		0,
		0,
	)
	if errno != 0 {
		return debugCheck{Name: "sysctl P_TRACED", Status: "ERROR", Details: fmt.Sprintf("sysctl query failed: %v", errno)}
	}

	// kp_proc.p_flag is at offset 32 in struct kinfo_proc on arm64/amd64 macOS
	// P_TRACED = 0x00000800
	const (
		kpProcPFlagOffset = 32
		pTraced           = 0x00000800
	)

	if len(buf) > kpProcPFlagOffset+4 {
		flags := *(*int32)(unsafe.Pointer(&buf[kpProcPFlagOffset]))
		if flags&pTraced != 0 {
			return debugCheck{Name: "sysctl P_TRACED", Status: "DETECTED", Details: "Process is being traced (debugger attached)"}
		}
		return debugCheck{Name: "sysctl P_TRACED", Status: "CLEAN", Details: "Not traced"}
	}

	return debugCheck{Name: "sysctl P_TRACED", Status: "ERROR", Details: "Buffer too small for kinfo_proc"}
}

// checkDyldInsertLibraries checks for DYLD_INSERT_LIBRARIES which may indicate library injection.
func checkDyldInsertLibraries() debugCheck {
	val := os.Getenv("DYLD_INSERT_LIBRARIES")
	if val != "" {
		return debugCheck{
			Name:    "DYLD_INSERT_LIBRARIES",
			Status:  "WARNING",
			Details: fmt.Sprintf("Set: %s", val),
		}
	}
	return debugCheck{Name: "DYLD_INSERT_LIBRARIES", Status: "CLEAN", Details: "Not set"}
}
