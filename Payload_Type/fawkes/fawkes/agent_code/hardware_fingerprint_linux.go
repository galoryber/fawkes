//go:build linux

package main

import (
	"os"
	"runtime"
	"strings"
)

// collectHardwareAttributes gathers stable hardware identifiers on Linux.
// Components: CPU model name, machine-id, architecture.
func collectHardwareAttributes() []byte {
	var parts []string

	parts = append(parts, cpuModelFromProc())
	parts = append(parts, machineID())
	parts = append(parts, runtime.GOARCH)

	return []byte("linux:" + strings.Join(parts, "|"))
}

func getCPUBrand() string { return cpuModelFromProc() }

func cpuModelFromProc() string {
	data, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		return ""
	}
	defer zeroBytes(data)
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "model name") {
			if idx := strings.Index(line, ":"); idx >= 0 {
				return strings.TrimSpace(line[idx+1:])
			}
		}
	}
	return ""
}

func machineID() string {
	data, err := os.ReadFile("/etc/machine-id")
	if err != nil {
		data, err = os.ReadFile("/var/lib/dbus/machine-id")
	}
	if err != nil {
		return ""
	}
	defer zeroBytes(data)
	return strings.TrimSpace(string(data))
}
