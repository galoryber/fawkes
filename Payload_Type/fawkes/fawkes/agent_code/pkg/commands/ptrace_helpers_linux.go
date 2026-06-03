//go:build linux

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

// checkYamaScope reads /proc/sys/kernel/yama/ptrace_scope and returns the
// scope value and a human-readable hint. Returns -1 if Yama is not loaded.
func checkYamaScope() (int, string) {
	data, err := os.ReadFile("/proc/sys/kernel/yama/ptrace_scope")
	if err != nil {
		return -1, "Yama LSM not loaded — ptrace unrestricted"
	}
	val := strings.TrimSpace(string(data))
	structs.ZeroBytes(data)

	var scope int
	if _, err := fmt.Sscanf(val, "%d", &scope); err != nil {
		return -1, "could not parse ptrace_scope"
	}

	switch scope {
	case 0:
		return 0, ""
	case 1:
		return 1, "Yama ptrace_scope=1 (restricted): only parent can ptrace child processes. " +
			"Use hollow (spawns child) or run as root/CAP_SYS_PTRACE for cross-process injection."
	case 2:
		return 2, "Yama ptrace_scope=2 (admin-only): requires CAP_SYS_PTRACE or root."
	case 3:
		return 3, "Yama ptrace_scope=3 (disabled): ptrace is completely disabled on this system."
	default:
		return scope, fmt.Sprintf("Yama ptrace_scope=%d (unknown)", scope)
	}
}
