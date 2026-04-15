//go:build linux && amd64

package commands

import (
	"fmt"
	"os"
)

// writeProcMem writes data to a target process's memory via /proc/PID/mem.
// Requires ptrace attachment or same-user permissions.
func writeProcMem(memPath string, addr uint64, data []byte) (int, error) {
	f, err := os.OpenFile(memPath, os.O_WRONLY, 0)
	if err != nil {
		return 0, fmt.Errorf("open %s: %w", memPath, err)
	}
	defer f.Close()

	n, err := f.WriteAt(data, int64(addr))
	if err != nil {
		return 0, fmt.Errorf("/proc/mem write at 0x%X: %w", addr, err)
	}
	return n, nil
}
