//go:build !windows
// +build !windows

package commands

import (
	"fmt"
	"syscall"

	"fawkes/pkg/structs"
)

// SuspendCommand suspends or resumes a process by PID.
type SuspendCommand struct{}

func (c *SuspendCommand) Name() string        { return "suspend" }
func (c *SuspendCommand) Description() string { return "Suspend or resume a process by PID" }

func (c *SuspendCommand) Execute(task structs.Task) structs.CommandResult {
	params, parseErr := unmarshalParams[SuspendParams](task)
	if parseErr != nil {
		return *parseErr
	}

	if params.PID <= 0 {
		return errorResult("Error: PID must be greater than 0")
	}

	if params.Action == "" {
		params.Action = "suspend"
	}

	// Resolve process name before action (best effort)
	procName := killGetProcessNameUnix(params.PID)
	pidLabel := fmt.Sprintf("%d", params.PID)
	if procName != "" {
		pidLabel = fmt.Sprintf("%d (%s)", params.PID, procName)
	}

	switch params.Action {
	case "suspend":
		// SIGSTOP cannot be caught or ignored — process is unconditionally stopped
		err := syscall.Kill(params.PID, syscall.SIGSTOP)
		if err != nil {
			return errorf("Failed to suspend process %s: %v", pidLabel, err)
		}
		return successf("Process %s suspended (SIGSTOP). Use 'suspend -action resume -pid %d' to resume.", pidLabel, params.PID)

	case "resume":
		err := syscall.Kill(params.PID, syscall.SIGCONT)
		if err != nil {
			return errorf("Failed to resume process %s: %v", pidLabel, err)
		}
		return successf("Process %s resumed (SIGCONT).", pidLabel)

	default:
		return errorf("Unknown action: %s. Use: suspend, resume", params.Action)
	}
}
