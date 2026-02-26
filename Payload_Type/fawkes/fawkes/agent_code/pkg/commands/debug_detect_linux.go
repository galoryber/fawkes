//go:build linux

package commands

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// runPlatformDebugChecks runs Linux-specific anti-debug checks.
func runPlatformDebugChecks() []debugCheck {
	var checks []debugCheck

	checks = append(checks, checkTracerPid())
	checks = append(checks, checkLdPreload())

	return checks
}

// checkTracerPid reads /proc/self/status for TracerPid field.
// A non-zero TracerPid means a debugger (GDB, strace, ltrace) is attached via ptrace.
func checkTracerPid() debugCheck {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return debugCheck{Name: "TracerPid (/proc/self/status)", Status: "ERROR", Details: fmt.Sprintf("Failed to read: %v", err)}
	}

	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "TracerPid:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				pidStr := strings.TrimSpace(parts[1])
				pid, _ := strconv.Atoi(pidStr)
				if pid > 0 {
					return debugCheck{
						Name:    "TracerPid (/proc/self/status)",
						Status:  "DETECTED",
						Details: fmt.Sprintf("Traced by PID %d", pid),
					}
				}
				return debugCheck{Name: "TracerPid (/proc/self/status)", Status: "CLEAN", Details: "TracerPid: 0"}
			}
		}
	}

	return debugCheck{Name: "TracerPid (/proc/self/status)", Status: "ERROR", Details: "TracerPid field not found"}
}

// checkLdPreload checks for LD_PRELOAD environment variable which may indicate library injection/hooking.
func checkLdPreload() debugCheck {
	val := os.Getenv("LD_PRELOAD")
	if val != "" {
		return debugCheck{
			Name:    "LD_PRELOAD",
			Status:  "WARNING",
			Details: fmt.Sprintf("Set: %s", val),
		}
	}
	return debugCheck{Name: "LD_PRELOAD", Status: "CLEAN", Details: "Not set"}
}
