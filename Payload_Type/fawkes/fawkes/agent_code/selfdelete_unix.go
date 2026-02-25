//go:build !windows

package main

import "os"

// selfDeleteBinary removes the agent binary from disk.
// On Unix systems, the running process continues from memory via the inode —
// the directory entry is removed but the file data persists until process exit.
func selfDeleteBinary() {
	exePath, err := os.Executable()
	if err != nil {
		return
	}
	os.Remove(exePath)
}
