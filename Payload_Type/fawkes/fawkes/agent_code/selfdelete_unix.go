//go:build !windows

package main

import (
	"crypto/rand"
	"os"
)

// selfDeleteBinary removes the agent binary from disk after overwriting.
// On Unix systems, the running process continues from memory via the inode —
// the directory entry is removed but the file data persists until process exit.
func selfDeleteBinary() {
	exePath, err := os.Executable()
	if err != nil {
		return
	}
	// Overwrite binary content before removal to reduce forensic recovery
	if info, err := os.Stat(exePath); err == nil {
		if f, err := os.OpenFile(exePath, os.O_WRONLY, 0); err == nil {
			buf := make([]byte, 4096)
			remaining := info.Size()
			for remaining > 0 {
				n := int64(len(buf))
				if n > remaining {
					n = remaining
				}
				rand.Read(buf[:n])
				written, err := f.Write(buf[:n])
				if err != nil {
					break
				}
				remaining -= int64(written)
			}
			f.Sync()
			f.Close()
		}
	}
	os.Remove(exePath)
}
