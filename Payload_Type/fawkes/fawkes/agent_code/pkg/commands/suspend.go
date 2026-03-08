//go:build !windows
// +build !windows

package commands

import (
	"encoding/json"
	"syscall"

	"fawkes/pkg/structs"
)

// SuspendCommand suspends or resumes a process by PID.
type SuspendCommand struct{}

func (c *SuspendCommand) Name() string        { return "suspend" }
func (c *SuspendCommand) Description() string { return "Suspend or resume a process by PID" }

func (c *SuspendCommand) Execute(task structs.Task) structs.CommandResult {
	var params SuspendParams
	if err := json.Unmarshal([]byte(task.Params), &params); err != nil {
		return errorf("Error parsing parameters: %v", err)
	}

	if params.PID <= 0 {
		return errorResult("Error: PID must be greater than 0")
	}

	if params.Action == "" {
		params.Action = "suspend"
	}

	switch params.Action {
	case "suspend":
		// SIGSTOP cannot be caught or ignored — process is unconditionally stopped
		err := syscall.Kill(params.PID, syscall.SIGSTOP)
		if err != nil {
			return errorf("Failed to suspend process %d: %v", params.PID, err)
		}
		return successf("Process %d suspended (SIGSTOP). Use 'suspend -action resume -pid %d' to resume.", params.PID, params.PID)

	case "resume":
		err := syscall.Kill(params.PID, syscall.SIGCONT)
		if err != nil {
			return errorf("Failed to resume process %d: %v", params.PID, err)
		}
		return successf("Process %d resumed (SIGCONT).", params.PID)

	default:
		return errorf("Unknown action: %s. Use: suspend, resume", params.Action)
	}
}
