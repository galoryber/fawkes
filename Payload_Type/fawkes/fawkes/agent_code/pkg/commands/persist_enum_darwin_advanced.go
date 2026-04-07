//go:build darwin

package commands

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"
)

func persistEnumAuthPlugins(sb *strings.Builder) int {
	sb.WriteString("--- Authorization Plugins ---\n")
	count := 0

	pluginDir := "/Library/Security/SecurityAgentPlugins"
	entries, err := os.ReadDir(pluginDir)
	if err != nil {
		sb.WriteString("  (directory not readable)\n\n")
		return 0
	}

	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(name, ".") {
			continue
		}
		info, _ := entry.Info()
		detail := ""
		if info != nil {
			detail = fmt.Sprintf(" (modified: %s)", info.ModTime().Format("2006-01-02 15:04"))
		}
		sb.WriteString(fmt.Sprintf("  [!] %s%s\n", name, detail))
		count++
	}

	if count == 0 {
		sb.WriteString("  (none found)\n")
	}
	sb.WriteString("\n")
	return count
}

// persistEnumEmond checks for Event Monitor daemon rules (T1546.014).
func persistEnumEmond(sb *strings.Builder) int {
	sb.WriteString("--- Emond Rules ---\n")
	count := 0

	emondDir := "/etc/emond.d/rules"
	entries, err := os.ReadDir(emondDir)
	if err != nil {
		sb.WriteString("  (directory not readable)\n\n")
		return 0
	}

	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || strings.HasPrefix(name, ".") {
			continue
		}
		if !strings.HasSuffix(name, ".plist") {
			continue
		}
		info, _ := entry.Info()
		detail := ""
		if info != nil {
			detail = fmt.Sprintf(" (modified: %s, size: %d)", info.ModTime().Format("2006-01-02 15:04"), info.Size())
		}
		sb.WriteString(fmt.Sprintf("  [!] %s%s\n", name, detail))
		count++
	}

	if count == 0 {
		sb.WriteString("  (none found)\n")
	}
	sb.WriteString("\n")
	return count
}

// persistEnumAtJobs checks for scheduled at(1) jobs.
func persistEnumAtJobs(sb *strings.Builder) int {
	sb.WriteString("--- At Jobs ---\n")
	count := 0

	atDir := "/var/at/jobs"
	entries, err := os.ReadDir(atDir)
	if err != nil {
		sb.WriteString("  (directory not readable)\n\n")
		return 0
	}

	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || strings.HasPrefix(name, ".") {
			continue
		}
		info, _ := entry.Info()
		detail := ""
		if info != nil {
			detail = fmt.Sprintf(" (modified: %s, size: %d)", info.ModTime().Format("2006-01-02 15:04"), info.Size())
		}
		sb.WriteString(fmt.Sprintf("  %s%s\n", name, detail))
		count++
	}

	if count == 0 {
		sb.WriteString("  (none found)\n")
	}
	sb.WriteString("\n")
	return count
}

// persistEnumSSHKeysDarwin checks for SSH authorized keys, private keys, and agent sockets (T1098.004).
func persistEnumSSHKeysDarwin(sb *strings.Builder) int {
	sb.WriteString("--- SSH Authorized Keys ---\n")
	count := 0

	homeDir := getHomeDirDarwin()
	authKeysPath := filepath.Join(homeDir, ".ssh/authorized_keys")

	if content, err := os.ReadFile(authKeysPath); err == nil {
		for _, line := range strings.Split(string(content), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				sb.WriteString(fmt.Sprintf("  %s %s...%s %s\n", parts[0], parts[1][:min(20, len(parts[1]))], parts[1][max(0, len(parts[1])-8):], parts[2]))
			} else if len(parts) >= 2 {
				sb.WriteString(fmt.Sprintf("  %s %s...%s\n", parts[0], parts[1][:min(20, len(parts[1]))], parts[1][max(0, len(parts[1])-8):]))
			} else {
				sb.WriteString(fmt.Sprintf("  %s\n", line[:min(80, len(line))]))
			}
			count++
		}
	}

	// Also check root if accessible
	if homeDir != "/var/root" {
		rootAuthKeys := "/var/root/.ssh/authorized_keys"
		if content, err := os.ReadFile(rootAuthKeys); err == nil {
			for _, line := range strings.Split(string(content), "\n") {
				line = strings.TrimSpace(line)
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				parts := strings.Fields(line)
				if len(parts) >= 3 {
					sb.WriteString(fmt.Sprintf("  [root] %s %s...%s %s\n", parts[0], parts[1][:min(20, len(parts[1]))], parts[1][max(0, len(parts[1])-8):], parts[2]))
				} else {
					sb.WriteString(fmt.Sprintf("  [root] %s\n", line[:min(80, len(line))]))
				}
				count++
			}
		}
	}

	if count == 0 {
		sb.WriteString("  (none found)\n")
	}

	// SSH private keys
	keyFiles := []string{"id_rsa", "id_ecdsa", "id_ed25519", "id_dsa"}
	sshDir := filepath.Join(homeDir, ".ssh")
	for _, name := range keyFiles {
		keyPath := filepath.Join(sshDir, name)
		info, err := os.Stat(keyPath)
		if err != nil {
			continue
		}
		encrypted := "plaintext"
		if content, err := os.ReadFile(keyPath); err == nil {
			if strings.Contains(string(content), "ENCRYPTED") {
				encrypted = "encrypted"
			}
			structs.ZeroBytes(content)
		}
		sb.WriteString(fmt.Sprintf("  [private key] %s (%d bytes, %s)\n", name, info.Size(), encrypted))
		count++
	}

	// SSH agent sockets
	if sock := os.Getenv("SSH_AUTH_SOCK"); sock != "" {
		sb.WriteString(fmt.Sprintf("  [agent socket] SSH_AUTH_SOCK=%s\n", sock))
		count++
	}
	// macOS launchd-managed SSH agent sockets (commonly under /tmp)
	if entries, err := filepath.Glob("/tmp/com.apple.launchd.*/Listeners"); err == nil {
		for _, entry := range entries {
			sb.WriteString(fmt.Sprintf("  [agent socket] %s\n", entry))
			count++
		}
	}

	sb.WriteString("\n")
	return count
}

func getHomeDirDarwin() string {
	if u, err := user.Current(); err == nil {
		return u.HomeDir
	}
	if home := os.Getenv("HOME"); home != "" {
		return home
	}
	return "/Users/Shared"
}
