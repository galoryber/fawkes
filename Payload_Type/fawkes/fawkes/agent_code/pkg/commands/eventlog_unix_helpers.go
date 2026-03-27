//go:build !windows

package commands

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"fawkes/pkg/structs"
)

// parseTimeWindow parses duration strings like "24h", "7d", "30m".
func parseTimeWindow(s string) (time.Duration, bool) {
	s = strings.TrimSpace(strings.ToLower(s))
	if len(s) < 2 {
		return 0, false
	}

	suffix := s[len(s)-1]
	numStr := s[:len(s)-1]

	var multiplier time.Duration
	switch suffix {
	case 'm':
		multiplier = time.Minute
	case 'h':
		multiplier = time.Hour
	case 'd':
		multiplier = 24 * time.Hour
	default:
		return 0, false
	}

	var num int
	if _, err := fmt.Sscanf(numStr, "%d", &num); err != nil || num <= 0 {
		return 0, false
	}

	return time.Duration(num) * multiplier, true
}

// eventlogQueryFile reads a log file directly (no subprocess — opsec friendly).
func eventlogQueryFile(path, filter string, maxCount int) structs.CommandResult {
	content, err := os.ReadFile(path)
	if err != nil {
		return errorf("Error reading %s: %v", path, err)
	}

	lines := strings.Split(strings.TrimRight(string(content), "\n"), "\n")

	// Apply keyword filter
	if filter != "" {
		if dur, ok := parseTimeWindow(filter); ok {
			// Time filter — parse syslog timestamps
			cutoff := time.Now().Add(-dur)
			lines = filterLinesByTime(lines, cutoff)
		} else {
			lowerFilter := strings.ToLower(filter)
			var filtered []string
			for _, line := range lines {
				if strings.Contains(strings.ToLower(line), lowerFilter) {
					filtered = append(filtered, line)
				}
			}
			lines = filtered
		}
	}

	// Return last N lines (newest)
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("=== %s (%d lines", path, len(lines)))
	if filter != "" {
		sb.WriteString(fmt.Sprintf(", filter: '%s'", filter))
	}
	sb.WriteString(") ===\n")

	start := 0
	if len(lines) > maxCount {
		start = len(lines) - maxCount
		sb.WriteString(fmt.Sprintf("(showing last %d lines)\n", maxCount))
	}
	for i := start; i < len(lines); i++ {
		sb.WriteString(lines[i] + "\n")
	}

	if len(lines) == 0 {
		sb.WriteString("No matching entries found.\n")
	}

	return successResult(sb.String())
}

// filterLinesByTime filters syslog-formatted lines to those after cutoff.
// Syslog format: "Mar 11 08:00:00 ..." or "Mar  9 08:00:00 ..." — parsed
// relative to current year. Uses "Jan _2 15:04:05" (space-padded day).
func filterLinesByTime(lines []string, cutoff time.Time) []string {
	year := time.Now().Year()
	var result []string
	for _, line := range lines {
		if len(line) < 15 {
			continue
		}
		// Syslog timestamp is always 15 chars: "Jan _2 15:04:05" format
		ts, err := time.Parse("Jan _2 15:04:05", line[:15])
		if err != nil {
			continue
		}
		ts = ts.AddDate(year-ts.Year(), 0, 0)
		if ts.After(cutoff) {
			result = append(result, line)
		}
	}
	return result
}

// eventlogFileInfo shows metadata about a specific log file.
func eventlogFileInfo(path string) structs.CommandResult {
	info, err := os.Stat(path)
	if err != nil {
		return errorf("Error: %v", err)
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Log File Info: %s\n\n", path))
	sb.WriteString(fmt.Sprintf("  Size:     %s (%d bytes)\n", formatBytes(uint64(info.Size())), info.Size()))
	sb.WriteString(fmt.Sprintf("  Modified: %s\n", info.ModTime().Format("2006-01-02 15:04:05 MST")))
	sb.WriteString(fmt.Sprintf("  Mode:     %s\n", info.Mode()))

	// Count lines if it's a text file and reasonably sized
	if info.Size() > 0 && info.Size() < 100*1024*1024 { // < 100MB
		if content, err := os.ReadFile(path); err == nil {
			lineCount := strings.Count(string(content), "\n")
			sb.WriteString(fmt.Sprintf("  Lines:    %d\n", lineCount))
		}
	}

	return successResult(sb.String())
}

// eventlogListVarLog lists text log files in /var/log with optional filter.
func eventlogListVarLog(sb *strings.Builder, filter string) int {
	entries, err := os.ReadDir("/var/log")
	if err != nil {
		sb.WriteString(fmt.Sprintf("  Error reading /var/log: %v\n", err))
		return 0
	}
	count := 0
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		// Skip binary/compressed files
		if strings.HasSuffix(name, ".gz") || strings.HasSuffix(name, ".xz") ||
			strings.HasSuffix(name, ".bz2") || strings.HasSuffix(name, ".zst") {
			continue
		}
		if filter != "" && !strings.Contains(strings.ToLower(name), strings.ToLower(filter)) {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		modTime := info.ModTime().Format("2006-01-02 15:04:05")
		sb.WriteString(fmt.Sprintf("  %-30s %10d bytes  %s\n", name, info.Size(), modTime))
		count++
	}
	return count
}

// dirSize calculates total size of files in a directory tree.
func dirSize(path string) int64 {
	var total int64
	_ = filepath.Walk(path, func(_ string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // skip errors
		}
		if !info.IsDir() {
			total += info.Size()
		}
		return nil
	})
	return total
}
