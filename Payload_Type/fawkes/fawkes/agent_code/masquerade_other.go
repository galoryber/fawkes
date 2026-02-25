//go:build !linux

package main

// masqueradeProcess is a no-op on non-Linux platforms.
// Linux uses prctl(PR_SET_NAME) to change /proc/self/comm.
// Windows/macOS process names are derived from the executable filename.
func masqueradeProcess(name string) {
	// No-op: process name masquerading is Linux-specific
}
