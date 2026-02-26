//go:build windows
// +build windows

package main

import (
	"os"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// getEnvironmentDomain returns the domain/workgroup the system belongs to.
func getEnvironmentDomain() string {
	// Try USERDNSDOMAIN first (full DNS domain like "contoso.com")
	if domain := os.Getenv("USERDNSDOMAIN"); domain != "" {
		return domain
	}
	// Fall back to USERDOMAIN (NetBIOS domain like "CONTOSO")
	if domain := os.Getenv("USERDOMAIN"); domain != "" {
		return domain
	}
	return ""
}

// isProcessRunning checks if a process with the given name is currently running.
func isProcessRunning(name string) bool {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return false
	}
	defer windows.CloseHandle(snapshot)

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))

	err = windows.Process32First(snapshot, &entry)
	if err != nil {
		return false
	}

	target := strings.ToLower(name)
	for {
		exeName := strings.ToLower(windows.UTF16ToString(entry.ExeFile[:]))
		if exeName == target {
			return true
		}
		err = windows.Process32Next(snapshot, &entry)
		if err != nil {
			break
		}
	}
	return false
}
