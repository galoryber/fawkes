//go:build linux && amd64

package commands

import (
	"fmt"
	"os"
	"strings"

	"fawkes/pkg/structs"
)

// findSyscallGadget scans r-xp memory regions for an x86-64 syscall instruction (0x0F 0x05).
func findSyscallGadget(pid int) (uint64, error) {
	mapsPath := fmt.Sprintf("/proc/%d/maps", pid)
	data, err := os.ReadFile(mapsPath)
	if err != nil {
		return 0, fmt.Errorf("cannot read %s: %w", mapsPath, err)
	}
	defer structs.ZeroBytes(data)

	memPath := fmt.Sprintf("/proc/%d/mem", pid)
	memFile, err := os.Open(memPath)
	if err != nil {
		return 0, fmt.Errorf("cannot open %s: %w", memPath, err)
	}
	defer memFile.Close()

	for _, line := range strings.Split(string(data), "\n") {
		if line == "" {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}

		perms := parts[1]
		if len(perms) < 4 || perms[0] != 'r' || perms[2] != 'x' {
			continue
		}
		if len(parts) >= 6 {
			name := parts[len(parts)-1]
			if strings.Contains(name, "vdso") || strings.Contains(name, "vsyscall") {
				continue
			}
		}

		addrParts := strings.Split(parts[0], "-")
		if len(addrParts) != 2 {
			continue
		}
		var startAddr, endAddr uint64
		if _, err := fmt.Sscanf(addrParts[0], "%x", &startAddr); err != nil {
			continue
		}
		if _, err := fmt.Sscanf(addrParts[1], "%x", &endAddr); err != nil {
			continue
		}

		chunkSize := uint64(4096)
		buf := make([]byte, chunkSize)
		for addr := startAddr; addr < endAddr-1; addr += chunkSize {
			readSize := chunkSize
			if addr+readSize > endAddr {
				readSize = endAddr - addr
			}
			n, err := memFile.ReadAt(buf[:readSize], int64(addr))
			if err != nil || n < 2 {
				break
			}
			for i := 0; i < n-1; i++ {
				if buf[i] == 0x0F && buf[i+1] == 0x05 {
					return addr + uint64(i), nil
				}
			}
		}
	}

	return 0, fmt.Errorf("no syscall gadget found in process %d", pid)
}
