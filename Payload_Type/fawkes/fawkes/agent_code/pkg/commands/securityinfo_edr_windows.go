//go:build windows

package commands

import (
	"fmt"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// getRunningProcessNamesWindows enumerates running processes via Windows API.
func getRunningProcessNamesWindows() map[string]int {
	procs := make(map[string]int)

	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return procs
	}
	defer windows.CloseHandle(snapshot)

	var pe windows.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))

	err = windows.Process32First(snapshot, &pe)
	for err == nil {
		name := strings.ToLower(windows.UTF16ToString(pe.ExeFile[:]))
		// Strip .exe suffix for matching
		name = strings.TrimSuffix(name, ".exe")
		procs[name] = int(pe.ProcessID)

		// Also store with .exe for exact match
		fullName := strings.ToLower(windows.UTF16ToString(pe.ExeFile[:]))
		procs[fullName] = int(pe.ProcessID)

		err = windows.Process32Next(snapshot, &pe)
	}

	// Also check for Windows-specific EDR install paths via registry
	checkWindowsEDRRegistry(procs)

	return procs
}

// checkWindowsEDRRegistry checks common registry locations for installed security products.
func checkWindowsEDRRegistry(procs map[string]int) {
	// WMI-based AV detection path
	output := runQuietCommand("powershell", "-NoProfile", "-Command",
		"Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction SilentlyContinue | Select-Object -ExpandProperty displayName")
	if output != "" {
		for _, line := range strings.Split(output, "\n") {
			name := strings.TrimSpace(line)
			if name != "" {
				// Use a sentinel PID of -1 to indicate "found via WMI, not process"
				key := fmt.Sprintf("wmi:%s", strings.ToLower(name))
				procs[key] = -1
			}
		}
	}
}
