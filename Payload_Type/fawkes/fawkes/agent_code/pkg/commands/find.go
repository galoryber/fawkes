package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"fawkes/pkg/structs"
)

type FindCommand struct{}

func (c *FindCommand) Name() string {
	return "find"
}

func (c *FindCommand) Description() string {
	return "Search for files by name pattern"
}

type FindParams struct {
	Path    string `json:"path"`
	Pattern string `json:"pattern"`
	MaxDepth int   `json:"max_depth"`
}

func (c *FindCommand) Execute(task structs.Task) structs.CommandResult {
	var params FindParams
	if err := json.Unmarshal([]byte(task.Params), &params); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error parsing parameters: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	if params.Path == "" {
		params.Path = "."
	}
	if params.Pattern == "" {
		return structs.CommandResult{
			Output:    "Error: pattern is required",
			Status:    "error",
			Completed: true,
		}
	}
	if params.MaxDepth <= 0 {
		params.MaxDepth = 10
	}

	// Resolve the starting path
	startPath, err := filepath.Abs(params.Path)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error resolving path: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	startDepth := strings.Count(startPath, string(os.PathSeparator))

	var matches []string
	const maxResults = 500

	err = filepath.Walk(startPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // skip inaccessible entries
		}

		// Check depth limit
		currentDepth := strings.Count(path, string(os.PathSeparator)) - startDepth
		if currentDepth > params.MaxDepth {
			if info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		// Match filename against pattern
		matched, _ := filepath.Match(params.Pattern, info.Name())
		if matched {
			sizeStr := ""
			if !info.IsDir() {
				sizeStr = formatFileSize(info.Size())
			} else {
				sizeStr = "<DIR>"
			}
			matches = append(matches, fmt.Sprintf("%-12s %s", sizeStr, path))
			if len(matches) >= maxResults {
				return fmt.Errorf("result limit reached")
			}
		}
		return nil
	})

	if len(matches) == 0 {
		return structs.CommandResult{
			Output:    fmt.Sprintf("No files matching '%s' found in %s (max_depth=%d)", params.Pattern, startPath, params.MaxDepth),
			Status:    "success",
			Completed: true,
		}
	}

	output := fmt.Sprintf("Found %d match(es) for '%s' in %s:\n\n%s",
		len(matches), params.Pattern, startPath, strings.Join(matches, "\n"))
	if len(matches) >= maxResults {
		output += fmt.Sprintf("\n\n(results truncated at %d)", maxResults)
	}

	return structs.CommandResult{
		Output:    output,
		Status:    "success",
		Completed: true,
	}
}

func formatFileSize(bytes int64) string {
	const (
		KB = 1024
		MB = KB * 1024
		GB = MB * 1024
	)
	switch {
	case bytes >= GB:
		return fmt.Sprintf("%.1f GB", float64(bytes)/float64(GB))
	case bytes >= MB:
		return fmt.Sprintf("%.1f MB", float64(bytes)/float64(MB))
	case bytes >= KB:
		return fmt.Sprintf("%.1f KB", float64(bytes)/float64(KB))
	default:
		return fmt.Sprintf("%d B", bytes)
	}
}
