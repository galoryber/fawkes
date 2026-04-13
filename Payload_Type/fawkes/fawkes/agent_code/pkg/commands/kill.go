//go:build !windows
// +build !windows

package commands

import (
	"fmt"
	"os"
	"runtime"
	"strings"

	"fawkes/pkg/structs"
)

// KillCommand implements the kill command (non-Windows)
type KillCommand struct{}

func (c *KillCommand) Name() string {
	return "kill"
}

func (c *KillCommand) Description() string {
	return "Terminate a process by PID"
}

func (c *KillCommand) Execute(task structs.Task) structs.CommandResult {
	params, parseErr := unmarshalParams[KillParams](task)
	if parseErr != nil {
		return *parseErr
	}

	pid := params.PID
	if pid <= 0 {
		return errorResult("Error: PID must be greater than 0")
	}

	// Get process name before killing (best effort)
	procName := killGetProcessNameUnix(pid)

	proc, err := os.FindProcess(pid)
	if err != nil {
		return errorf("Error finding process %d: %v", pid, err)
	}

	err = proc.Kill()
	if err != nil {
		return errorf("Error killing process %d: %v", pid, err)
	}

	if procName != "" {
		return successf("Successfully terminated process %d (%s)", pid, procName)
	}
	return successf("Successfully terminated process %d", pid)
}

// killGetProcessNameUnix resolves a PID to its process name without spawning a subprocess.
// Linux: reads /proc/<pid>/comm. Darwin: reads /proc not available, uses ps.
func killGetProcessNameUnix(pid int) string {
	if runtime.GOOS == "linux" {
		data, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
		if err != nil {
			return ""
		}
		return strings.TrimSpace(string(data))
	}
	// macOS: no /proc filesystem; best-effort via ps (spawns process but only way)
	if runtime.GOOS == "darwin" {
		out, err := execCmdTimeoutOutput("ps", "-p", fmt.Sprintf("%d", pid), "-o", "comm=")
		if err != nil {
			return ""
		}
		name := strings.TrimSpace(string(out))
		// ps returns full path on macOS — extract basename
		if idx := strings.LastIndex(name, "/"); idx >= 0 {
			name = name[idx+1:]
		}
		return name
	}
	return ""
}
