package commands

import (
	"encoding/json"
	"fmt"
	"os"
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
	Action    string `json:"action"`    // "copy", "set", "get"
	Target    string `json:"target"`    // Target file to modify
	Source    string `json:"source"`    // Source file to copy timestamps from (for "copy")
	Timestamp string `json:"timestamp"` // Timestamp string (for "set")
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
	default:
		return errorf("Error: unknown action '%s'. Valid actions: get, copy, set", params.Action)
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

	return structs.CommandResult{
		Output:    output,
		Status:    "success",
		Completed: true,
	}
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

	return structs.CommandResult{
		Output:    output,
		Status:    "success",
		Completed: true,
	}
}

// timestompSet sets timestamps to a specific time
func timestompSet(target, timestamp string) structs.CommandResult {
	if timestamp == "" {
		return errorResult("Error: timestamp is required for set action (format: 2006-01-02T15:04:05Z or 2006-01-02 15:04:05)")
	}

	// Try multiple timestamp formats
	var t time.Time
	var err error
	formats := []string{
		time.RFC3339,
		"2006-01-02T15:04:05",
		"2006-01-02 15:04:05",
		"2006-01-02",
		"01/02/2006 15:04:05",
		"01/02/2006",
	}

	for _, format := range formats {
		t, err = time.Parse(format, timestamp)
		if err == nil {
			break
		}
	}

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
