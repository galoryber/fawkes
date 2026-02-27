//go:build !windows

package commands

import (
	"fmt"
	"os"
	"runtime"
	"strings"
)

func proxyCheckPlatform() string {
	switch runtime.GOOS {
	case "linux":
		return proxyCheckLinux()
	case "darwin":
		return proxyCheckDarwin()
	default:
		return ""
	}
}

func proxyCheckLinux() string {
	var sb strings.Builder
	sb.WriteString("[*] System Proxy Files:\n")

	// Check apt proxy
	if data, err := os.ReadFile("/etc/apt/apt.conf.d/proxy.conf"); err == nil {
		sb.WriteString(fmt.Sprintf("    /etc/apt/apt.conf.d/proxy.conf:\n    %s\n", strings.TrimSpace(string(data))))
	}

	// Check /etc/environment for proxy
	if data, err := os.ReadFile("/etc/environment"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			lower := strings.ToLower(line)
			if strings.Contains(lower, "proxy") {
				sb.WriteString(fmt.Sprintf("    /etc/environment: %s\n", strings.TrimSpace(line)))
			}
		}
	}

	// Check /etc/profile.d for proxy scripts
	if entries, err := os.ReadDir("/etc/profile.d"); err == nil {
		for _, e := range entries {
			if strings.Contains(strings.ToLower(e.Name()), "proxy") {
				path := "/etc/profile.d/" + e.Name()
				if data, err := os.ReadFile(path); err == nil {
					sb.WriteString(fmt.Sprintf("    %s: %s\n", path, truncate(strings.TrimSpace(string(data)), 200)))
				}
			}
		}
	}

	return sb.String()
}

func proxyCheckDarwin() string {
	var sb strings.Builder
	sb.WriteString("[*] macOS Network Proxy:\n")

	if data, err := os.ReadFile("/Library/Preferences/SystemConfiguration/preferences.plist"); err == nil {
		content := string(data)
		if strings.Contains(content, "ProxyAutoConfig") || strings.Contains(content, "HTTPProxy") || strings.Contains(content, "SOCKSProxy") {
			sb.WriteString("    System preferences contain proxy configuration\n")
		} else {
			sb.WriteString("    No proxy in system preferences\n")
		}
	}

	return sb.String()
}
