//go:build linux

package commands

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"fawkes/pkg/structs"
)

// persistEnumShellProfiles checks shell configuration files for modifications.
func persistEnumShellProfiles(sb *strings.Builder) int {
	sb.WriteString("--- Shell Profiles ---\n")
	count := 0

	homeDir := currentHomeDir()

	// System-wide profiles
	systemProfiles := []string{"/etc/profile", "/etc/bash.bashrc", "/etc/zsh/zshrc"}
	for _, path := range systemProfiles {
		if info, err := os.Stat(path); err == nil {
			sb.WriteString(fmt.Sprintf("  %s (modified: %s, size: %d)\n", path, info.ModTime().Format("2006-01-02 15:04"), info.Size()))
			count++
		}
	}

	// /etc/profile.d/ scripts
	if entries, err := os.ReadDir("/etc/profile.d"); err == nil {
		for _, entry := range entries {
			if entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
				continue
			}
			sb.WriteString(fmt.Sprintf("  /etc/profile.d/%s\n", entry.Name()))
			count++
		}
	}

	// User profiles
	userProfiles := []string{".bashrc", ".bash_profile", ".profile", ".zshrc", ".zshenv", ".zprofile"}
	for _, name := range userProfiles {
		path := filepath.Join(homeDir, name)
		if info, err := os.Stat(path); err == nil {
			sb.WriteString(fmt.Sprintf("  %s (modified: %s, size: %d)\n", path, info.ModTime().Format("2006-01-02 15:04"), info.Size()))
			count++
		}
	}

	if count == 0 {
		sb.WriteString("  (none found)\n")
	}
	sb.WriteString("\n")
	return count
}

// persistEnumStartup checks init.d scripts, rc.local, and XDG autostart.
func persistEnumStartup(sb *strings.Builder) int {
	sb.WriteString("--- Startup / Init ---\n")
	count := 0

	// rc.local
	if content, err := os.ReadFile("/etc/rc.local"); err == nil {
		lines := strings.Split(string(content), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") || line == "exit 0" {
				continue
			}
			sb.WriteString(fmt.Sprintf("  [rc.local] %s\n", line))
			count++
		}
	}

	// /etc/init.d/ non-default scripts
	if entries, err := os.ReadDir("/etc/init.d"); err == nil {
		for _, entry := range entries {
			name := entry.Name()
			if entry.IsDir() || strings.HasPrefix(name, ".") || name == "README" {
				continue
			}
			sb.WriteString(fmt.Sprintf("  [init.d] %s\n", name))
			count++
		}
	}

	// XDG autostart entries
	homeDir := currentHomeDir()
	autostartDirs := []string{
		filepath.Join(homeDir, ".config/autostart"),
		"/etc/xdg/autostart",
	}
	for _, dir := range autostartDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if !strings.HasSuffix(entry.Name(), ".desktop") {
				continue
			}
			sb.WriteString(fmt.Sprintf("  [%s] %s\n", dir, entry.Name()))
			count++
		}
	}

	if count == 0 {
		sb.WriteString("  (none found)\n")
	}
	sb.WriteString("\n")
	return count
}

// persistEnumMotd checks for MOTD (Message of the Day) scripts that run on login (T1546).
func persistEnumMotd(sb *strings.Builder) int {
	sb.WriteString("--- MOTD Scripts ---\n")
	count := 0

	motdDirs := []string{"/etc/update-motd.d", "/etc/profile.d"}

	for _, dir := range motdDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
				continue
			}
			// For /etc/profile.d only show .sh files (they're sourced on login)
			if dir == "/etc/profile.d" && !strings.HasSuffix(entry.Name(), ".sh") {
				continue
			}
			// For update-motd.d, skip if already counted in startup check
			if dir == "/etc/update-motd.d" {
				info, err := entry.Info()
				if err != nil {
					continue
				}
				mode := info.Mode()
				if mode&0111 == 0 {
					continue // Not executable
				}
				sb.WriteString(fmt.Sprintf("  [%s] %s (%s)\n", dir, entry.Name(), mode.String()))
				count++
			}
		}
	}

	// Also check /etc/motd for static MOTD
	if info, err := os.Stat("/etc/motd"); err == nil && info.Size() > 0 {
		sb.WriteString(fmt.Sprintf("  [/etc/motd] static message (%d bytes)\n", info.Size()))
		count++
	}

	if count == 0 {
		sb.WriteString("  (none found)\n")
	}
	sb.WriteString("\n")
	return count
}

// persistEnumSSHKeys checks for SSH authorized_keys files.
func persistEnumSSHKeys(sb *strings.Builder) int {
	sb.WriteString("--- SSH Authorized Keys ---\n")
	count := 0

	homeDir := currentHomeDir()
	authKeysPath := filepath.Join(homeDir, ".ssh/authorized_keys")

	if content, err := os.ReadFile(authKeysPath); err == nil {
		lines := strings.Split(string(content), "\n")
		structs.ZeroBytes(content) // opsec: clear SSH authorized_keys data
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			// Truncate long key data, show type and comment
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

	// Also check /root/.ssh/authorized_keys if accessible
	if homeDir != "/root" {
		rootAuthKeys := "/root/.ssh/authorized_keys"
		if content, err := os.ReadFile(rootAuthKeys); err == nil {
			rootLines := strings.Split(string(content), "\n")
			structs.ZeroBytes(content) // opsec: clear SSH authorized_keys data
			for _, line := range rootLines {
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

	// SSH private keys — indicate key-based auth capability
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

	// SSH agent sockets — hijackable for lateral movement
	if sock := os.Getenv("SSH_AUTH_SOCK"); sock != "" {
		sb.WriteString(fmt.Sprintf("  [agent socket] SSH_AUTH_SOCK=%s\n", sock))
		count++
	}
	// Scan /tmp/ssh-* for agent sockets from other sessions
	if entries, err := filepath.Glob("/tmp/ssh-*/agent.*"); err == nil {
		for _, entry := range entries {
			info, err := os.Stat(entry)
			if err != nil {
				continue
			}
			if info.Mode()&os.ModeSocket != 0 {
				sb.WriteString(fmt.Sprintf("  [agent socket] %s\n", entry))
				count++
			}
		}
	}

	sb.WriteString("\n")
	return count
}
