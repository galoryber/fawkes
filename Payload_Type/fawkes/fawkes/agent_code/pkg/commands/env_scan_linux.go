//go:build linux
// +build linux

package commands

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"fawkes/pkg/structs"
)

// readProcessEnviron reads environment variables from /proc/<pid>/environ.
func readProcessEnviron(pid int) ([]string, string, error) {
	procDir := filepath.Join("/proc", strconv.Itoa(pid))

	// Read process name from /proc/<pid>/comm
	processName := fmt.Sprintf("pid-%d", pid)
	if comm, err := os.ReadFile(filepath.Join(procDir, "comm")); err == nil {
		processName = strings.TrimSpace(string(comm))
	}

	// Read environment from /proc/<pid>/environ
	data, err := os.ReadFile(filepath.Join(procDir, "environ"))
	if err != nil {
		return nil, processName, fmt.Errorf("cannot read environ: %v", err)
	}

	return parseEnvironBlock(data), processName, nil
}

// envScanAllProcesses scans all accessible processes for sensitive env vars.
func envScanAllProcesses(filter string) structs.CommandResult {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return errorf("Failed to read /proc: %v", err)
	}

	var allResults []envScanResult
	totalProcesses := 0
	accessibleProcesses := 0

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		totalProcesses++

		envVars, processName, err := readProcessEnviron(pid)
		if err != nil {
			continue // permission denied or process exited
		}
		accessibleProcesses++

		results := filterSensitiveVars(envVars, pid, processName)
		allResults = append(allResults, results...)
	}

	// Deduplicate: same variable from parent/child processes
	allResults = deduplicateResults(allResults)

	// Apply user filter
	if filter != "" {
		allResults = applyEnvFilter(allResults, filter)
	}

	output := formatEnvScanResults(allResults, totalProcesses, accessibleProcesses)
	return structs.CommandResult{
		Output:    output,
		Status:    "success",
		Completed: true,
	}
}

// deduplicateResults removes duplicate findings (same variable+value from forked processes).
func deduplicateResults(results []envScanResult) []envScanResult {
	type key struct {
		variable string
		value    string
	}
	seen := make(map[key]bool)
	var deduped []envScanResult

	for _, r := range results {
		k := key{r.Variable, r.Value}
		if !seen[k] {
			seen[k] = true
			deduped = append(deduped, r)
		}
	}
	return deduped
}
