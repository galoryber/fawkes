//go:build darwin

package main

import (
	"os/exec"
	"runtime"
	"strings"
)

// collectHardwareAttributes gathers stable hardware identifiers on macOS.
// Components: CPU brand string, hardware UUID, architecture.
func collectHardwareAttributes() []byte {
	var parts []string

	parts = append(parts, cpuBrandSysctl())
	parts = append(parts, platformUUID())
	parts = append(parts, runtime.GOARCH)

	return []byte("darwin:" + strings.Join(parts, "|"))
}

func getCPUBrand() string { return cpuBrandSysctl() }

func cpuBrandSysctl() string {
	out, err := exec.Command("sysctl", "-n", "machdep.cpu.brand_string").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func platformUUID() string {
	out, err := exec.Command("ioreg", "-rd1", "-c", "IOPlatformExpertDevice").Output()
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, "IOPlatformUUID") {
			if idx := strings.Index(line, "="); idx >= 0 {
				val := strings.TrimSpace(line[idx+1:])
				val = strings.Trim(val, "\" ")
				return val
			}
		}
	}
	return ""
}
