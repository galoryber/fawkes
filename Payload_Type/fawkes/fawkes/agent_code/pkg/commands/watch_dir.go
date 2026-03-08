package commands

import (
	"crypto/md5"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"fawkes/pkg/structs"
)

// WatchDirCommand monitors a directory for file system changes
type WatchDirCommand struct{}

func (c *WatchDirCommand) Name() string        { return "watch-dir" }
func (c *WatchDirCommand) Description() string { return "Monitor a directory for file system changes" }

type watchDirParams struct {
	Path     string `json:"path"`
	Interval int    `json:"interval"` // Poll interval in seconds (default 5)
	Duration int    `json:"duration"` // Max duration in seconds (0 = until stopped via jobkill)
	Depth    int    `json:"depth"`    // Max directory depth (default 3)
	Pattern  string `json:"pattern"`  // Glob pattern filter (e.g., "*.docx")
	Hash     bool   `json:"hash"`     // Use MD5 for change detection (slower but catches in-place edits)
}

// fileSnapshot holds metadata for a single file at a point in time
type fileSnapshot struct {
	Size    int64
	ModTime time.Time
	Hash    string // MD5 hex, only if hash=true
}

// watchEvent represents a detected file system change
type watchEvent struct {
	Time   time.Time
	Action string // CREATED, MODIFIED, DELETED
	Path   string
	Detail string // size change, new file info, etc.
}

func (c *WatchDirCommand) Execute(task structs.Task) structs.CommandResult {
	var params watchDirParams
	if err := json.Unmarshal([]byte(task.Params), &params); err != nil {
		return errorf("Error parsing parameters: %v", err)
	}

	if params.Path == "" {
		return errorResult("Error: 'path' is required")
	}
	if params.Interval <= 0 {
		params.Interval = 5
	}
	if params.Depth <= 0 {
		params.Depth = 3
	}

	targetPath, err := filepath.Abs(params.Path)
	if err != nil {
		return errorf("Error resolving path: %v", err)
	}

	info, err := os.Stat(targetPath)
	if err != nil {
		return errorf("Error accessing path: %v", err)
	}
	if !info.IsDir() {
		return errorf("Error: %s is not a directory", targetPath)
	}

	// Take initial snapshot
	baseline := scanDirectory(targetPath, params.Depth, params.Pattern, params.Hash)

	var events []watchEvent
	startTime := time.Now()
	pollInterval := time.Duration(params.Interval) * time.Second
	maxDuration := time.Duration(params.Duration) * time.Second

	// Poll loop — exits on task cancellation or duration limit
	for !task.DidStop() && (maxDuration == 0 || time.Since(startTime) < maxDuration) {
		// Sleep with cancellation checks
		sleepEnd := time.Now().Add(pollInterval)
		for time.Now().Before(sleepEnd) && !task.DidStop() {
			if maxDuration > 0 && time.Since(startTime) >= maxDuration {
				break
			}
			time.Sleep(500 * time.Millisecond)
		}

		if task.DidStop() || (maxDuration > 0 && time.Since(startTime) >= maxDuration) {
			break
		}

		// Take new snapshot and compare
		current := scanDirectory(targetPath, params.Depth, params.Pattern, params.Hash)
		newEvents := compareSnapshots(baseline, current, params.Hash)
		events = append(events, newEvents...)

		// Update baseline to current state
		baseline = current
	}

	return watchDirFormatResult(targetPath, events, startTime, params)
}

// scanDirectory walks a directory up to maxDepth and returns file metadata
func scanDirectory(root string, maxDepth int, pattern string, doHash bool) map[string]fileSnapshot {
	result := make(map[string]fileSnapshot)

	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // skip inaccessible files
		}

		// Check depth
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return nil
		}
		if rel == "." {
			return nil // skip root itself
		}
		parts := strings.Split(rel, string(os.PathSeparator))
		// For directories, depth = number of components (a/b = depth 2)
		// For files, depth = number of parent dirs (a/b/file.txt = depth 2)
		dirDepth := len(parts)
		if !d.IsDir() {
			dirDepth = len(parts) - 1
		}
		if dirDepth > maxDepth {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		// Skip directories — we only track files
		if d.IsDir() {
			return nil
		}

		// Apply pattern filter
		if pattern != "" {
			matched, matchErr := filepath.Match(pattern, filepath.Base(path))
			if matchErr != nil || !matched {
				return nil
			}
		}

		// Get full file info only for entries passing all filters
		info, infoErr := d.Info()
		if infoErr != nil {
			return nil
		}

		snap := fileSnapshot{
			Size:    info.Size(),
			ModTime: info.ModTime(),
		}

		if doHash {
			snap.Hash = watchDirHashFile(path)
		}

		result[rel] = snap
		return nil
	})

	return result
}

// compareSnapshots detects changes between two directory snapshots
func compareSnapshots(baseline, current map[string]fileSnapshot, doHash bool) []watchEvent {
	var events []watchEvent
	now := time.Now()

	// Check for new and modified files
	for path, cur := range current {
		if base, exists := baseline[path]; exists {
			// File existed before — check for modifications
			modified := false
			var detail string

			if doHash && cur.Hash != base.Hash {
				modified = true
				detail = "content changed"
			} else if cur.Size != base.Size {
				modified = true
				detail = fmt.Sprintf("size: %d → %d", base.Size, cur.Size)
			} else if !cur.ModTime.Equal(base.ModTime) {
				modified = true
				detail = fmt.Sprintf("mtime: %s → %s",
					base.ModTime.Format("15:04:05"),
					cur.ModTime.Format("15:04:05"))
			}

			if modified {
				events = append(events, watchEvent{
					Time:   now,
					Action: "MODIFIED",
					Path:   path,
					Detail: detail,
				})
			}
		} else {
			// New file
			events = append(events, watchEvent{
				Time:   now,
				Action: "CREATED",
				Path:   path,
				Detail: fmt.Sprintf("size: %d", cur.Size),
			})
		}
	}

	// Check for deleted files
	for path := range baseline {
		if _, exists := current[path]; !exists {
			events = append(events, watchEvent{
				Time:   now,
				Action: "DELETED",
				Path:   path,
				Detail: "",
			})
		}
	}

	// Sort events by action for consistent output
	sort.Slice(events, func(i, j int) bool {
		if events[i].Action != events[j].Action {
			return events[i].Action < events[j].Action
		}
		return events[i].Path < events[j].Path
	})

	return events
}

// watchDirHashFile computes MD5 of a file, returns empty string on error
func watchDirHashFile(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()

	h := md5.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}

// watchDirFormatResult builds the output summary
func watchDirFormatResult(targetPath string, events []watchEvent, startTime time.Time, params watchDirParams) structs.CommandResult {
	duration := time.Since(startTime).Truncate(time.Second)

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Directory Watch Report: %s\n", targetPath))
	sb.WriteString(fmt.Sprintf("Duration: %s | Interval: %ds | Depth: %d",
		duration, params.Interval, params.Depth))
	if params.Pattern != "" {
		sb.WriteString(fmt.Sprintf(" | Pattern: %s", params.Pattern))
	}
	if params.Hash {
		sb.WriteString(" | MD5 hashing: enabled")
	}
	sb.WriteString("\n")

	if len(events) == 0 {
		sb.WriteString("\nNo changes detected.")
		return structs.CommandResult{
			Output:    sb.String(),
			Status:    "completed",
			Completed: true,
		}
	}

	// Count by type
	created, modified, deleted := 0, 0, 0
	for _, e := range events {
		switch e.Action {
		case "CREATED":
			created++
		case "MODIFIED":
			modified++
		case "DELETED":
			deleted++
		}
	}
	sb.WriteString(fmt.Sprintf("Changes: %d total (%d created, %d modified, %d deleted)\n",
		len(events), created, modified, deleted))
	sb.WriteString(strings.Repeat("-", 80) + "\n")

	// Format events chronologically
	for _, e := range events {
		ts := e.Time.Format("15:04:05")
		line := fmt.Sprintf("[%s] %-10s %s", ts, e.Action, e.Path)
		if e.Detail != "" {
			line += fmt.Sprintf("  (%s)", e.Detail)
		}
		sb.WriteString(line + "\n")
	}

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "completed",
		Completed: true,
	}
}
