//go:build windows

package commands

import (
	"fmt"
	"strings"

	"golang.org/x/sys/windows/registry"
)

func proxyCheckPlatform() string {
	var sb strings.Builder
	sb.WriteString("[*] Windows Internet Settings (Registry):\n")

	k, err := registry.OpenKey(registry.CURRENT_USER,
		`Software\Microsoft\Windows\CurrentVersion\Internet Settings`, registry.QUERY_VALUE)
	if err != nil {
		sb.WriteString(fmt.Sprintf("    Error reading registry: %v\n", err))
		return sb.String()
	}
	defer k.Close()

	// ProxyEnable
	proxyEnable, _, err := k.GetIntegerValue("ProxyEnable")
	if err == nil {
		if proxyEnable == 1 {
			sb.WriteString("    ProxyEnable: 1 (enabled)\n")
		} else {
			sb.WriteString("    ProxyEnable: 0 (disabled)\n")
		}
	}

	// ProxyServer
	proxyServer, _, err := k.GetStringValue("ProxyServer")
	if err == nil && proxyServer != "" {
		sb.WriteString(fmt.Sprintf("    ProxyServer: %s\n", proxyServer))
	}

	// ProxyOverride (bypass list)
	proxyOverride, _, err := k.GetStringValue("ProxyOverride")
	if err == nil && proxyOverride != "" {
		sb.WriteString(fmt.Sprintf("    ProxyOverride: %s\n", proxyOverride))
	}

	// AutoConfigURL (PAC file)
	autoConfig, _, err := k.GetStringValue("AutoConfigURL")
	if err == nil && autoConfig != "" {
		sb.WriteString(fmt.Sprintf("    AutoConfigURL: %s\n", autoConfig))
	}

	// WinHTTP proxy (machine-level)
	sb.WriteString("\n[*] WinHTTP Settings:\n")
	wk, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections`, registry.QUERY_VALUE)
	if err == nil {
		defer wk.Close()
		if data, _, err := wk.GetBinaryValue("WinHttpSettings"); err == nil && len(data) > 0 {
			sb.WriteString(fmt.Sprintf("    WinHttpSettings: %d bytes configured\n", len(data)))
		} else {
			sb.WriteString("    WinHttpSettings: not configured\n")
		}
	}

	return sb.String()
}
