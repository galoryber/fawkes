//go:build !windows
// +build !windows

package main

import "os"

func getIntegrityLevel() int {
	// Integrity levels for Mythic:
	// 1 = Low integrity (untrusted)
	// 2 = Medium integrity (standard user)
	// 3 = High integrity (administrator - not used on Unix)
	// 4 = System integrity (root)

	// For Unix-like systems, check if running as root (UID 0)
	if os.Geteuid() == 0 {
		return 4 // root
	}

	// For non-root users on Unix, return medium integrity
	return 2
}
