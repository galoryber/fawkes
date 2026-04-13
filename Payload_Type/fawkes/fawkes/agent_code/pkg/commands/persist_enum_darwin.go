//go:build darwin

package commands

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"fawkes/pkg/structs"
)

// PersistEnumCommand enumerates macOS persistence mechanisms.
type PersistEnumCommand struct{}

func (c *PersistEnumCommand) Name() string { return "persist-enum" }
func (c *PersistEnumCommand) Description() string {
	return "Enumerate macOS persistence mechanisms — LaunchAgents, LaunchDaemons, login items, shell profiles, cron, auth plugins, emond, at jobs, SSH keys (T1547)"
}

func (c *PersistEnumCommand) Execute(task structs.Task) structs.CommandResult {
	args, parseErr := unmarshalParams[persistEnumArgs](task)
	if parseErr != nil {
		return *parseErr
	}
	if args.Category == "" {
		args.Category = "all"
	}

	var sb strings.Builder
	sb.WriteString("=== Persistence Enumeration (macOS) ===\n\n")

	cat := strings.ToLower(args.Category)
	found := 0

	if cat == "all" || cat == "launchd" {
		found += persistEnumLaunchAgents(&sb)
	}
	if cat == "all" || cat == "cron" {
		found += persistEnumCronDarwin(&sb)
	}
	if cat == "all" || cat == "shell" {
		found += persistEnumShellProfilesDarwin(&sb)
	}
	if cat == "all" || cat == "login" {
		found += persistEnumLoginItems(&sb)
	}
	if cat == "all" || cat == "periodic" {
		found += persistEnumPeriodic(&sb)
	}
	if cat == "all" || cat == "authplugins" {
		found += persistEnumAuthPlugins(&sb)
	}
	if cat == "all" || cat == "emond" {
		found += persistEnumEmond(&sb)
	}
	if cat == "all" || cat == "at" {
		found += persistEnumAtJobs(&sb)
	}
	if cat == "all" || cat == "ssh" {
		found += persistEnumSSHKeysDarwin(&sb)
	}

	sb.WriteString(fmt.Sprintf("\n=== Total: %d persistence items found ===\n", found))

	return successResult(sb.String())
}

// persistEnumLaunchAgents enumerates LaunchAgents and LaunchDaemons.
func persistEnumLaunchAgents(sb *strings.Builder) int {
	sb.WriteString("--- LaunchAgents / LaunchDaemons ---\n")
	count := 0

	homeDir := getHomeDirDarwin()
	dirs := []struct {
		path string
		desc string
	}{
		{filepath.Join(homeDir, "Library/LaunchAgents"), "User LaunchAgents"},
		{"/Library/LaunchAgents", "System LaunchAgents"},
		{"/Library/LaunchDaemons", "System LaunchDaemons"},
	}

	for _, d := range dirs {
		entries, err := os.ReadDir(d.path)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			name := entry.Name()
			if entry.IsDir() || strings.HasPrefix(name, ".") {
				continue
			}
			if !strings.HasSuffix(name, ".plist") {
				continue
			}
			// Skip Apple system plists
			if strings.HasPrefix(name, "com.apple.") {
				continue
			}

			info, err := entry.Info()
			detail := ""
			if err == nil {
				detail = fmt.Sprintf(" (modified: %s)", info.ModTime().Format("2006-01-02 15:04"))
			}
			sb.WriteString(fmt.Sprintf("  [%s] %s%s\n", d.desc, name, detail))
			count++
		}
	}

	if count == 0 {
		sb.WriteString("  (only Apple system items)\n")
	}
	sb.WriteString("\n")
	return count
}

// persistEnumCronDarwin checks cron jobs on macOS.
func persistEnumCronDarwin(sb *strings.Builder) int {
	sb.WriteString("--- Cron Jobs ---\n")
	count := 0

	// System crontab
	if content, err := os.ReadFile("/etc/crontab"); err == nil {
		for _, line := range strings.Split(string(content), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			sb.WriteString(fmt.Sprintf("  [/etc/crontab] %s\n", line))
			count++
		}
	}

	// User crontabs
	cronDirs := []string{"/usr/lib/cron/tabs", "/var/at/tabs"}
	for _, cronDir := range cronDirs {
		entries, err := os.ReadDir(cronDir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			path := filepath.Join(cronDir, entry.Name())
			content, err := os.ReadFile(path)
			if err != nil {
				continue
			}
			for _, line := range strings.Split(string(content), "\n") {
				line = strings.TrimSpace(line)
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				sb.WriteString(fmt.Sprintf("  [%s] %s\n", entry.Name(), line))
				count++
			}
		}
	}

	if count == 0 {
		sb.WriteString("  (none found)\n")
	}
	sb.WriteString("\n")
	return count
}

// persistEnumShellProfilesDarwin checks shell configuration files.
func persistEnumShellProfilesDarwin(sb *strings.Builder) int {
	sb.WriteString("--- Shell Profiles ---\n")
	count := 0

	homeDir := getHomeDirDarwin()

	profiles := []string{".zshrc", ".zshenv", ".zprofile", ".bashrc", ".bash_profile", ".profile"}
	for _, name := range profiles {
		path := filepath.Join(homeDir, name)
		if info, err := os.Stat(path); err == nil {
			sb.WriteString(fmt.Sprintf("  %s (modified: %s, size: %d)\n", path, info.ModTime().Format("2006-01-02 15:04"), info.Size()))
			count++
		}
	}

	// System profiles
	systemProfiles := []string{"/etc/profile", "/etc/zshrc", "/etc/bashrc"}
	for _, path := range systemProfiles {
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

// persistEnumLoginItems checks login items and login hooks.
func persistEnumLoginItems(sb *strings.Builder) int {
	sb.WriteString("--- Login Items / Hooks ---\n")
	count := 0

	// Check for login hook via defaults
	out, err := execCmdTimeoutOutput("defaults", "read", "com.apple.loginwindow", "LoginHook")
	if err == nil {
		hook := strings.TrimSpace(string(out))
		if hook != "" {
			sb.WriteString(fmt.Sprintf("  [LoginHook] %s\n", hook))
			count++
		}
	}

	out, err = execCmdTimeoutOutput("defaults", "read", "com.apple.loginwindow", "LogoutHook")
	if err == nil {
		hook := strings.TrimSpace(string(out))
		if hook != "" {
			sb.WriteString(fmt.Sprintf("  [LogoutHook] %s\n", hook))
			count++
		}
	}

	// Check SSH authorized_keys
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
				sb.WriteString(fmt.Sprintf("  [authorized_keys] %s %s...%s %s\n", parts[0], parts[1][:min(20, len(parts[1]))], parts[1][max(0, len(parts[1])-8):], parts[2]))
			} else {
				sb.WriteString(fmt.Sprintf("  [authorized_keys] %s\n", line[:min(80, len(line))]))
			}
			count++
		}
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

	if count == 0 {
		sb.WriteString("  (none found)\n")
	}
	sb.WriteString("\n")
	return count
}

// persistEnumPeriodic checks /etc/periodic for custom scripts.
func persistEnumPeriodic(sb *strings.Builder) int {
	sb.WriteString("--- Periodic Scripts ---\n")
	count := 0

	periodicDirs := []string{"/etc/periodic/daily", "/etc/periodic/weekly", "/etc/periodic/monthly"}
	for _, dir := range periodicDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			name := entry.Name()
			if entry.IsDir() || strings.HasPrefix(name, ".") {
				continue
			}
			sb.WriteString(fmt.Sprintf("  [%s] %s\n", filepath.Base(dir), name))
			count++
		}
	}

	if count == 0 {
		sb.WriteString("  (none found)\n")
	}
	sb.WriteString("\n")
	return count
}

// persistEnumAuthPlugins checks for SecurityAgent authorization plugins (T1547.002).
