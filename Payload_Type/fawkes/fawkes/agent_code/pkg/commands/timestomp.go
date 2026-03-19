package commands

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"fawkes/pkg/structs"
)

// TimestompCommand implements the timestomp command
type TimestompCommand struct{}

// Name returns the command name
func (c *TimestompCommand) Name() string {
	return "timestomp"
}

// Description returns the command description
func (c *TimestompCommand) Description() string {
	return "Modify file timestamps to blend in with surrounding files (T1070.006)"
}

// TimestompParams represents the parameters for timestomp
type TimestompParams struct {
	Action    string `json:"action"`    // "copy", "set", "get", "match", "random"
	Target    string `json:"target"`    // Target file to modify
	Source    string `json:"source"`    // Source file to copy timestamps from (for "copy")
	Timestamp string `json:"timestamp"` // Timestamp string (for "set"), or range end (for "random")
}

// Execute executes the timestomp command
func (c *TimestompCommand) Execute(task structs.Task) structs.CommandResult {
	var params TimestompParams
	if err := json.Unmarshal([]byte(task.Params), &params); err != nil {
		// Plain text fallback: "get /path", "copy /target /source", "set /path 2024-01-01T00:00:00Z"
		parts := strings.Fields(task.Params)
		if len(parts) >= 1 {
			params.Action = parts[0]
		}
		if len(parts) >= 2 {
			params.Target = parts[1]
		}
		if len(parts) >= 3 {
			switch params.Action {
			case "copy":
				params.Source = parts[2]
			case "set":
				params.Timestamp = parts[2]
			}
		}
	}

	if params.Target == "" {
		return errorResult("Error: target file path is required")
	}

	switch params.Action {
	case "get":
		return timestompGet(params.Target)
	case "copy":
		return timestompCopy(params.Target, params.Source)
	case "set":
		return timestompSet(params.Target, params.Timestamp)
	case "match":
		return timestompMatch(params.Target)
	case "random":
		return timestompRandom(params.Target, params.Source, params.Timestamp)
	default:
		return errorf("Error: unknown action '%s'. Valid actions: get, copy, set, match, random", params.Action)
	}
}

// timestompGet retrieves timestamps for a file
func timestompGet(target string) structs.CommandResult {
	info, err := os.Stat(target)
	if err != nil {
		return errorf("Error: %v", err)
	}

	output := fmt.Sprintf("Timestamps for: %s\n", target)
	output += fmt.Sprintf("  Modified:  %s\n", info.ModTime().Format(time.RFC3339))

	// Platform-specific timestamps (access time, creation time)
	output += getPlatformTimestamps(target, info)

	return successResult(output)
}

// timestompCopy copies timestamps from source to target
func timestompCopy(target, source string) structs.CommandResult {
	if source == "" {
		return errorResult("Error: source file path is required for copy action")
	}

	sourceInfo, err := os.Stat(source)
	if err != nil {
		return errorf("Error reading source file: %v", err)
	}

	// Get access time from platform-specific code
	atime := getAccessTime(source, sourceInfo)
	mtime := sourceInfo.ModTime()

	// Set access and modification times
	if err := os.Chtimes(target, atime, mtime); err != nil {
		return errorf("Error setting timestamps: %v", err)
	}

	// On Windows, also copy creation time
	if err := copyCreationTime(target, source); err != nil {
		// Non-fatal — access and modification times were already set
		return successf("Set access/modify times from %s, but failed to copy creation time: %v", source, err)
	}

	output := fmt.Sprintf("Copied timestamps from %s to %s\n", source, target)
	output += fmt.Sprintf("  Source modified:  %s\n", mtime.Format(time.RFC3339))
	output += fmt.Sprintf("  Source accessed:  %s\n", atime.Format(time.RFC3339))

	return successResult(output)
}

// timestompSet sets timestamps to a specific time
func timestompSet(target, timestamp string) structs.CommandResult {
	if timestamp == "" {
		return errorResult("Error: timestamp is required for set action (format: 2006-01-02T15:04:05Z or 2006-01-02 15:04:05)")
	}

	t, err := parseTimestamp(timestamp)
	if err != nil {
		return errorf("Error parsing timestamp '%s': %v\nSupported formats: RFC3339, YYYY-MM-DD HH:MM:SS, YYYY-MM-DD, MM/DD/YYYY", timestamp, err)
	}

	// Set access and modification times
	if err := os.Chtimes(target, t, t); err != nil {
		return errorf("Error setting timestamps: %v", err)
	}

	// On Windows, also set creation time
	if err := setCreationTime(target, t); err != nil {
		return successf("Set access/modify times to %s, but failed to set creation time: %v", t.Format(time.RFC3339), err)
	}

	return successf("Set all timestamps on %s to %s", target, t.Format(time.RFC3339))
}

// timestompMatch sets the target's timestamps to blend with neighboring files in the same directory.
// It collects modification times from all files in the directory, then picks a random time
// within the interquartile range (Q1-Q3) to avoid outlier timestamps.
func timestompMatch(target string) structs.CommandResult {
	dir := filepath.Dir(target)

	entries, err := os.ReadDir(dir)
	if err != nil {
		return errorf("Error reading directory: %v", err)
	}

	// Collect modification times from sibling files (skip the target itself)
	absTarget, _ := filepath.Abs(target)
	var mtimes []time.Time
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		fullPath := filepath.Join(dir, e.Name())
		absPath, _ := filepath.Abs(fullPath)
		if absPath == absTarget {
			continue
		}
		info, infoErr := e.Info()
		if infoErr != nil {
			continue
		}
		mtimes = append(mtimes, info.ModTime())
	}

	if len(mtimes) < 2 {
		return errorResult("Error: need at least 2 sibling files in the directory to match timestamps")
	}

	// Sort and use interquartile range to avoid outliers
	sort.Slice(mtimes, func(i, j int) bool { return mtimes[i].Before(mtimes[j]) })

	q1Idx := len(mtimes) / 4
	q3Idx := len(mtimes) * 3 / 4
	if q3Idx <= q1Idx {
		q3Idx = q1Idx + 1
	}
	rangeStart := mtimes[q1Idx]
	rangeEnd := mtimes[q3Idx]

	chosen, err := randomTimeBetween(rangeStart, rangeEnd)
	if err != nil {
		return errorf("Error generating random timestamp: %v", err)
	}

	if err := os.Chtimes(target, chosen, chosen); err != nil {
		return errorf("Error setting timestamps: %v", err)
	}
	if err := setCreationTime(target, chosen); err != nil {
		// Non-fatal
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Matched timestamps on %s to blend with directory\n", target))
	sb.WriteString(fmt.Sprintf("  Directory:    %s (%d sibling files)\n", dir, len(mtimes)))
	sb.WriteString(fmt.Sprintf("  Range (IQR):  %s — %s\n", rangeStart.Format(time.RFC3339), rangeEnd.Format(time.RFC3339)))
	sb.WriteString(fmt.Sprintf("  Set to:       %s\n", chosen.Format(time.RFC3339)))
	return successResult(sb.String())
}

// timestompRandom sets the target's timestamps to a random time within the given range.
// source = range start timestamp, timestamp = range end timestamp.
func timestompRandom(target, rangeStartStr, rangeEndStr string) structs.CommandResult {
	if rangeStartStr == "" || rangeEndStr == "" {
		return errorResult("Error: random action requires both source (range start) and timestamp (range end)")
	}

	rangeStart, err := parseTimestamp(rangeStartStr)
	if err != nil {
		return errorf("Error parsing range start: %v", err)
	}
	rangeEnd, err := parseTimestamp(rangeEndStr)
	if err != nil {
		return errorf("Error parsing range end: %v", err)
	}

	chosen, err := randomTimeBetween(rangeStart, rangeEnd)
	if err != nil {
		return errorf("Error: %v", err)
	}

	if err := os.Chtimes(target, chosen, chosen); err != nil {
		return errorf("Error setting timestamps: %v", err)
	}
	if err := setCreationTime(target, chosen); err != nil {
		// Non-fatal
	}

	return successf("Set timestamps on %s to random time: %s (range: %s — %s)",
		target, chosen.Format(time.RFC3339),
		rangeStart.Format(time.RFC3339), rangeEnd.Format(time.RFC3339))
}

// parseTimestamp tries multiple common formats to parse a timestamp string.
func parseTimestamp(s string) (time.Time, error) {
	formats := []string{
		time.RFC3339,
		"2006-01-02T15:04:05",
		"2006-01-02 15:04:05",
		"2006-01-02",
		"01/02/2006 15:04:05",
		"01/02/2006",
	}
	for _, f := range formats {
		if t, err := time.Parse(f, s); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("unsupported format '%s'", s)
}

// randomTimeBetween generates a cryptographically random time between start and end.
func randomTimeBetween(start, end time.Time) (time.Time, error) {
	if end.Before(start) {
		start, end = end, start
	}
	diff := end.Unix() - start.Unix()
	if diff <= 0 {
		return start, nil
	}

	// Use crypto/rand for unpredictable timestamp selection
	n, err := rand.Int(rand.Reader, big.NewInt(diff))
	if err != nil {
		// Fallback to deterministic midpoint
		var b [8]byte
		if _, rerr := rand.Read(b[:]); rerr != nil {
			return start.Add(time.Duration(diff/2) * time.Second), nil
		}
		offset := int64(binary.LittleEndian.Uint64(b[:])) % diff
		return start.Add(time.Duration(offset) * time.Second), nil
	}
	return start.Add(time.Duration(n.Int64()) * time.Second), nil
}
