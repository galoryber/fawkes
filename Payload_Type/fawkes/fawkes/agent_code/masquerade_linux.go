//go:build linux

package main

import (
	"syscall"
	"unsafe"
)

// masqueradeProcess changes the process name visible in /proc/self/comm,
// ps, top, and htop using prctl(PR_SET_NAME). Max 15 characters.
func masqueradeProcess(name string) {
	// PR_SET_NAME = 15, truncates to 15 chars (TASK_COMM_LEN - 1)
	nameBytes := append([]byte(name), 0)
	_, _, _ = syscall.Syscall6(
		syscall.SYS_PRCTL,
		15, // PR_SET_NAME
		uintptr(unsafe.Pointer(&nameBytes[0])),
		0, 0, 0, 0,
	)
}
