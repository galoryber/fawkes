//go:build linux && arm64

package commands

import (
	"fmt"
	"os"
	"strings"

	"fawkes/pkg/structs"
)

// findSyscallGadget scans r-xp memory regions for an ARM64 SVC #0 instruction (0x01 0x00 0x00 0xD4).
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
			if strings.Contains(name, "vdso") {
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
		for addr := startAddr; addr < endAddr-3; addr += chunkSize {
			readSize := chunkSize
			if addr+readSize > endAddr {
				readSize = endAddr - addr
			}
			n, err := memFile.ReadAt(buf[:readSize], int64(addr))
			if err != nil || n < 4 {
				break
			}
			// ARM64 instructions are 4-byte aligned
			alignStart := 0
			if offset := addr % 4; offset != 0 {
				alignStart = int(4 - offset)
			}
			for i := alignStart; i <= n-4; i += 4 {
				if buf[i] == 0x01 && buf[i+1] == 0x00 && buf[i+2] == 0x00 && buf[i+3] == 0xD4 {
					return addr + uint64(i), nil
				}
			}
		}
	}

	return 0, fmt.Errorf("no SVC gadget found in process %d", pid)
}
