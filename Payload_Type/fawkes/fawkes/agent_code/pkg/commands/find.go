package commands

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"fawkes/pkg/structs"
)

type FindCommand struct{}

func (c *FindCommand) Name() string {
	return "find"
}

func (c *FindCommand) Description() string {
	return "Search for files by name pattern with optional size, date, and type filters"
}

type FindParams struct {
	Path     string `json:"path"`
	Pattern  string `json:"pattern"`
	MaxDepth int    `json:"max_depth"`
	MinSize  int64  `json:"min_size"` // minimum file size in bytes (0 = no minimum)
	MaxSize  int64  `json:"max_size"` // maximum file size in bytes (0 = no maximum)
	Newer    int    `json:"newer"`    // modified within the last N minutes (0 = no filter)
	Older    int    `json:"older"`    // modified more than N minutes ago (0 = no filter)
	Type     string `json:"type"`     // "f" = files only, "d" = dirs only, "" = both
}

func (c *FindCommand) Execute(task structs.Task) structs.CommandResult {
	var params FindParams
	if err := json.Unmarshal([]byte(task.Params), &params); err != nil {
		params.Pattern = strings.TrimSpace(task.Params)
	}

	if params.Path == "" {
		params.Path = "."
	}
	if params.Pattern == "" {
		// Default pattern matches everything when using filters
		if params.MinSize > 0 || params.MaxSize > 0 || params.Newer > 0 || params.Older > 0 || params.Type != "" {
			params.Pattern = "*"
		} else {
			return errorResult("Error: pattern is required")
		}
	}
	if params.MaxDepth <= 0 {
		params.MaxDepth = 10
	}

	// Resolve the starting path
	startPath, err := filepath.Abs(params.Path)
	if err != nil {
		return errorf("Error resolving path: %v", err)
	}

	// Precompute time boundaries
	now := time.Now()
	var newerThan, olderThan time.Time
	if params.Newer > 0 {
		newerThan = now.Add(-time.Duration(params.Newer) * time.Minute)
	}
	if params.Older > 0 {
		olderThan = now.Add(-time.Duration(params.Older) * time.Minute)
	}

	startDepth := strings.Count(startPath, string(os.PathSeparator))

	var matches []string
	var accessErrors []string
	const maxResults = 500

	_ = filepath.WalkDir(startPath, func(path string, d fs.DirEntry, err error) error {
		if task.DidStop() {
			return fmt.Errorf("cancelled")
		}
		if err != nil {
			accessErrors = append(accessErrors, fmt.Sprintf("access denied: %s", path))
			return nil // skip inaccessible entries
		}

		// Check depth limit
		currentDepth := strings.Count(path, string(os.PathSeparator)) - startDepth
		if currentDepth > params.MaxDepth {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		// Type filter
		if params.Type == "f" && d.IsDir() {
			return nil
		}
		if params.Type == "d" && !d.IsDir() {
			return nil
		}

		// Match filename against pattern
		matched, _ := filepath.Match(params.Pattern, filepath.Base(path))
		if !matched {
			return nil
		}

		// Get full file info (Size/ModTime) only for entries that pass filters
		info, infoErr := d.Info()
		if infoErr != nil {
			return nil
		}

		// Size filters (only apply to files)
		if !d.IsDir() {
			if params.MinSize > 0 && info.Size() < params.MinSize {
				return nil
			}
			if params.MaxSize > 0 && info.Size() > params.MaxSize {
				return nil
			}
		}

		// Date filters
		modTime := info.ModTime()
		if params.Newer > 0 && modTime.Before(newerThan) {
			return nil
		}
		if params.Older > 0 && modTime.After(olderThan) {
			return nil
		}

		// Format output
		sizeStr := ""
		if !d.IsDir() {
			sizeStr = formatFileSize(info.Size())
		} else {
			sizeStr = "<DIR>"
		}

		timeStr := modTime.Format("2006-01-02 15:04")
		matches = append(matches, fmt.Sprintf("%-12s %-16s %s", sizeStr, timeStr, path))
		if len(matches) >= maxResults {
			return fmt.Errorf("result limit reached")
		}

		return nil
	})

	if len(matches) == 0 {
		output := fmt.Sprintf("No files matching '%s' found in %s", params.Pattern, startPath)
		output += findFilterSummary(params)
		if len(accessErrors) > 0 {
			output += fmt.Sprintf("\n\n%d path(s) inaccessible", len(accessErrors))
		}
		return structs.CommandResult{
			Output:    output,
			Status:    "success",
			Completed: true,
		}
	}

	output := fmt.Sprintf("Found %d match(es) for '%s' in %s:\n\n%s",
		len(matches), params.Pattern, startPath, strings.Join(matches, "\n"))
	if len(matches) >= maxResults {
		output += fmt.Sprintf("\n\n(results truncated at %d)", maxResults)
	}
	if len(accessErrors) > 0 {
		output += fmt.Sprintf("\n\n%d path(s) inaccessible", len(accessErrors))
	}

	return structs.CommandResult{
		Output:    output,
		Status:    "success",
		Completed: true,
	}
}

// findFilterSummary returns a human-readable summary of active filters
func findFilterSummary(params FindParams) string {
	var filters []string
	if params.MaxDepth != 10 {
		filters = append(filters, fmt.Sprintf("depth=%d", params.MaxDepth))
	}
	if params.MinSize > 0 {
		filters = append(filters, fmt.Sprintf("min_size=%s", formatFileSize(params.MinSize)))
	}
	if params.MaxSize > 0 {
		filters = append(filters, fmt.Sprintf("max_size=%s", formatFileSize(params.MaxSize)))
	}
	if params.Newer > 0 {
		filters = append(filters, fmt.Sprintf("newer=%dm", params.Newer))
	}
	if params.Older > 0 {
		filters = append(filters, fmt.Sprintf("older=%dm", params.Older))
	}
	if params.Type != "" {
		filters = append(filters, fmt.Sprintf("type=%s", params.Type))
	}
	if len(filters) > 0 {
		return fmt.Sprintf(" (filters: %s)", strings.Join(filters, ", "))
	}
	return ""
}

// formatFileSize moved to format_helpers.go
