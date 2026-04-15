//go:build linux && amd64

package commands

import (
	"fmt"
	"os"
	"strings"

	"fawkes/pkg/structs"
)

func ptraceCheck() structs.CommandResult {
	var sb strings.Builder

	sb.WriteString("Ptrace Configuration\n")
	sb.WriteString(strings.Repeat("=", 60) + "\n\n")

	if scope, err := os.ReadFile("/proc/sys/kernel/yama/ptrace_scope"); err == nil {
		val := strings.TrimSpace(string(scope))
		structs.ZeroBytes(scope)
		sb.WriteString(fmt.Sprintf("ptrace_scope: %s", val))
		switch val {
		case "0":
			sb.WriteString(" (classic — any process can ptrace same-UID processes)\n")
		case "1":
			sb.WriteString(" (restricted — only parent can ptrace child, or CAP_SYS_PTRACE)\n")
		case "2":
			sb.WriteString(" (admin-only — requires CAP_SYS_PTRACE)\n")
		case "3":
			sb.WriteString(" (disabled — no ptrace allowed)\n")
		default:
			sb.WriteString("\n")
		}
	} else {
		sb.WriteString("ptrace_scope: not available (Yama LSM not loaded)\n")
	}

	sb.WriteString(fmt.Sprintf("\nCurrent UID:  %d\n", os.Getuid()))
	sb.WriteString(fmt.Sprintf("Current EUID: %d\n", os.Geteuid()))

	if os.Geteuid() == 0 {
		sb.WriteString("\nRunning as root — ptrace should work on all processes\n")
	}

	if status, err := os.ReadFile("/proc/self/status"); err == nil {
		sb.WriteString("\nCapabilities:\n")
		for _, line := range strings.Split(string(status), "\n") {
			if strings.HasPrefix(line, "Cap") {
				sb.WriteString(fmt.Sprintf("  %s\n", line))
			}
		}
		structs.ZeroBytes(status)
	}

	sb.WriteString("\nCandidate Processes (same UID):\n")
	entries, _ := os.ReadDir("/proc")
	uid := os.Getuid()
	count := 0
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		var pid int
		if _, err := fmt.Sscanf(e.Name(), "%d", &pid); err != nil {
			continue
		}
		if pid == os.Getpid() {
			continue
		}
		statusPath := fmt.Sprintf("/proc/%d/status", pid)
		data, err := os.ReadFile(statusPath)
		if err != nil {
			continue
		}
		var procUID int
		var procName string
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "Name:") {
				procName = strings.TrimSpace(strings.TrimPrefix(line, "Name:"))
			}
			if strings.HasPrefix(line, "Uid:") {
				_, _ = fmt.Sscanf(strings.TrimPrefix(line, "Uid:"), "%d", &procUID)
			}
		}
		structs.ZeroBytes(data)
		if procUID == uid || os.Geteuid() == 0 {
			sb.WriteString(fmt.Sprintf("  PID %-7d %s\n", pid, procName))
			count++
			if count >= 20 {
				sb.WriteString("  ... (truncated)\n")
				break
			}
		}
	}

	return successResult(sb.String())
}

// findSyscallGadget scans r-xp memory regions for a syscall instruction (0x0F 0x05).
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
