//go:build darwin

package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"

	"fawkes/pkg/structs"
)

// PersistEnumCommand enumerates macOS persistence mechanisms.
type PersistEnumCommand struct{}

func (c *PersistEnumCommand) Name() string { return "persist-enum" }
func (c *PersistEnumCommand) Description() string {
	return "Enumerate macOS persistence mechanisms — LaunchAgents, LaunchDaemons, login items, shell profiles, cron (T1547)"
}

func (c *PersistEnumCommand) Execute(task structs.Task) structs.CommandResult {
	var args persistEnumArgs
	if task.Params != "" {
		if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
			return structs.CommandResult{
				Output:    fmt.Sprintf("Error parsing parameters: %v", err),
				Status:    "error",
				Completed: true,
			}
		}
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

	sb.WriteString(fmt.Sprintf("\n=== Total: %d persistence items found ===\n", found))

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
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

func getHomeDirDarwin() string {
	if u, err := user.Current(); err == nil {
		return u.HomeDir
	}
	if home := os.Getenv("HOME"); home != "" {
		return home
	}
	return "/Users/Shared"
}
