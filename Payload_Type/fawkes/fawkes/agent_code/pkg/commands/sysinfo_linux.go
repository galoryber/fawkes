//go:build linux

package commands

import (
	"fmt"
	"os"
	"strings"
	"time"
)

func collectPlatformSysinfo(sb *strings.Builder) {
	sb.WriteString("--- Linux Details ---\n")

	// OS release info
	if data, err := os.ReadFile("/etc/os-release"); err == nil {
		fields := parseOSRelease(string(data))
		if name, ok := fields["PRETTY_NAME"]; ok {
			sb.WriteString(fmt.Sprintf("Distribution:  %s\n", name))
		} else if name, ok := fields["NAME"]; ok {
			version := fields["VERSION"]
			sb.WriteString(fmt.Sprintf("Distribution:  %s %s\n", name, version))
		}
		if id, ok := fields["ID"]; ok {
			sb.WriteString(fmt.Sprintf("Distro ID:     %s\n", id))
		}
	}

	// Kernel version
	if data, err := os.ReadFile("/proc/version"); err == nil {
		line := strings.TrimSpace(string(data))
		// Extract kernel version string
		parts := strings.Fields(line)
		if len(parts) >= 3 {
			sb.WriteString(fmt.Sprintf("Kernel:        %s\n", parts[2]))
		}
	}

	// Memory info
	if data, err := os.ReadFile("/proc/meminfo"); err == nil {
		info := parseMeminfo(string(data))
		if total, ok := info["MemTotal"]; ok {
			sb.WriteString(fmt.Sprintf("Total Memory:  %s\n", total))
		}
		if avail, ok := info["MemAvailable"]; ok {
			sb.WriteString(fmt.Sprintf("Avail Memory:  %s\n", avail))
		}
	}

	// Uptime
	if data, err := os.ReadFile("/proc/uptime"); err == nil {
		fields := strings.Fields(strings.TrimSpace(string(data)))
		if len(fields) >= 1 {
			var secs float64
			if _, err := fmt.Sscanf(fields[0], "%f", &secs); err == nil {
				uptime := time.Duration(secs * float64(time.Second))
				days := int(uptime.Hours()) / 24
				hours := int(uptime.Hours()) % 24
				minutes := int(uptime.Minutes()) % 60
				sb.WriteString(fmt.Sprintf("Uptime:        %dd %dh %dm\n", days, hours, minutes))
				bootTime := time.Now().Add(-uptime)
				sb.WriteString(fmt.Sprintf("Boot Time:     %s\n", bootTime.Format("2006-01-02 15:04:05")))
			}
		}
	}

	// User ID and groups
	sb.WriteString(fmt.Sprintf("UID:           %d\n", os.Getuid()))
	sb.WriteString(fmt.Sprintf("EUID:          %d\n", os.Geteuid()))
	sb.WriteString(fmt.Sprintf("GID:           %d\n", os.Getgid()))

	// SELinux status
	if data, err := os.ReadFile("/sys/fs/selinux/enforce"); err == nil {
		mode := strings.TrimSpace(string(data))
		if mode == "1" {
			sb.WriteString("SELinux:       enforcing\n")
		} else {
			sb.WriteString("SELinux:       permissive\n")
		}
	} else {
		sb.WriteString("SELinux:       disabled\n")
	}

	// Virtualization detection
	if data, err := os.ReadFile("/sys/class/dmi/id/product_name"); err == nil {
		product := strings.TrimSpace(string(data))
		if product != "" {
			sb.WriteString(fmt.Sprintf("Hardware:      %s\n", product))
		}
	}
	if data, err := os.ReadFile("/sys/hypervisor/type"); err == nil {
		hypervisor := strings.TrimSpace(string(data))
		if hypervisor != "" {
			sb.WriteString(fmt.Sprintf("Hypervisor:    %s\n", hypervisor))
		}
	}
}

func parseOSRelease(content string) map[string]string {
	result := make(map[string]string)
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := parts[0]
		val := strings.Trim(parts[1], "\"")
		result[key] = val
	}
	return result
}

func parseMeminfo(content string) map[string]string {
	result := make(map[string]string)
	for _, line := range strings.Split(content, "\n") {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])
		result[key] = val
	}
	return result
}
