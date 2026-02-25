//go:build !windows
// +build !windows

package main

import (
	"os"
	"path/filepath"
	"strings"
)

// getEnvironmentDomain returns the domain/workgroup the system belongs to.
// On Unix, this extracts the domain from the FQDN hostname or checks common env vars.
func getEnvironmentDomain() string {
	// Check hostname for FQDN (e.g., "host.contoso.com" → "contoso.com")
	hostname, err := os.Hostname()
	if err == nil {
		if parts := strings.SplitN(hostname, ".", 2); len(parts) == 2 {
			return parts[1]
		}
	}
	// Check common environment variables
	if domain := os.Getenv("DOMAINNAME"); domain != "" {
		return domain
	}
	return ""
}

// isProcessRunning checks if a process with the given name is currently running.
// On Linux, reads /proc/<pid>/comm. On macOS, falls back to /proc if available.
func isProcessRunning(name string) bool {
	target := strings.ToLower(name)

	// Try /proc filesystem (Linux)
	entries, err := os.ReadDir("/proc")
	if err == nil {
		for _, entry := range entries {
			// Only check numeric directories (PIDs)
			if !entry.IsDir() {
				continue
			}
			pid := entry.Name()
			if len(pid) == 0 || pid[0] < '0' || pid[0] > '9' {
				continue
			}
			comm, err := os.ReadFile(filepath.Join("/proc", pid, "comm"))
			if err != nil {
				continue
			}
			procName := strings.ToLower(strings.TrimSpace(string(comm)))
			if procName == target {
				return true
			}
		}
		return false
	}

	// macOS fallback: /proc not available, check /dev/null exists as sanity check
	// and read from sysctl. For simplicity, skip process check on macOS if /proc unavailable.
	return false
}
