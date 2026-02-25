//go:build darwin

package commands

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

func collectPlatformSysinfo(sb *strings.Builder) {
	sb.WriteString("--- macOS Details ---\n")

	// OS version from sw_vers
	if out, err := exec.Command("sw_vers").Output(); err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				val := strings.TrimSpace(parts[1])
				switch key {
				case "ProductName":
					sb.WriteString(fmt.Sprintf("Product:       %s\n", val))
				case "ProductVersion":
					sb.WriteString(fmt.Sprintf("Version:       %s\n", val))
				case "BuildVersion":
					sb.WriteString(fmt.Sprintf("Build:         %s\n", val))
				}
			}
		}
	}

	// Kernel version
	if out, err := exec.Command("uname", "-r").Output(); err == nil {
		sb.WriteString(fmt.Sprintf("Kernel:        %s\n", strings.TrimSpace(string(out))))
	}

	// Hardware model
	if out, err := exec.Command("sysctl", "-n", "hw.model").Output(); err == nil {
		sb.WriteString(fmt.Sprintf("Model:         %s\n", strings.TrimSpace(string(out))))
	}

	// Memory
	if out, err := exec.Command("sysctl", "-n", "hw.memsize").Output(); err == nil {
		var memBytes uint64
		if _, err := fmt.Sscanf(strings.TrimSpace(string(out)), "%d", &memBytes); err == nil {
			sb.WriteString(fmt.Sprintf("Total Memory:  %s\n", formatFileSize(int64(memBytes))))
		}
	}

	// Uptime via sysctl kern.boottime
	if out, err := exec.Command("sysctl", "-n", "kern.boottime").Output(); err == nil {
		// Format: { sec = 1234567890, usec = 0 } ...
		outStr := strings.TrimSpace(string(out))
		var bootSec int64
		if _, err := fmt.Sscanf(outStr, "{ sec = %d", &bootSec); err == nil {
			bootTime := time.Unix(bootSec, 0)
			uptime := time.Since(bootTime)
			days := int(uptime.Hours()) / 24
			hours := int(uptime.Hours()) % 24
			minutes := int(uptime.Minutes()) % 60
			sb.WriteString(fmt.Sprintf("Uptime:        %dd %dh %dm\n", days, hours, minutes))
			sb.WriteString(fmt.Sprintf("Boot Time:     %s\n", bootTime.Format("2006-01-02 15:04:05")))
		}
	}

	// User info
	sb.WriteString(fmt.Sprintf("UID:           %d\n", os.Getuid()))
	sb.WriteString(fmt.Sprintf("EUID:          %d\n", os.Geteuid()))

	// SIP status
	if out, err := exec.Command("csrutil", "status").Output(); err == nil {
		status := strings.TrimSpace(string(out))
		if strings.Contains(status, "enabled") {
			sb.WriteString("SIP:           enabled\n")
		} else if strings.Contains(status, "disabled") {
			sb.WriteString("SIP:           disabled\n")
		}
	}
}
