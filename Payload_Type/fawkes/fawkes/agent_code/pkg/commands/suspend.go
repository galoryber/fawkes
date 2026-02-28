//go:build !windows
// +build !windows

package commands

import (
	"encoding/json"
	"fmt"
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
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error parsing parameters: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	if params.PID <= 0 {
		return structs.CommandResult{
			Output:    "Error: PID must be greater than 0",
			Status:    "error",
			Completed: true,
		}
	}

	if params.Action == "" {
		params.Action = "suspend"
	}

	switch params.Action {
	case "suspend":
		// SIGSTOP cannot be caught or ignored — process is unconditionally stopped
		err := syscall.Kill(params.PID, syscall.SIGSTOP)
		if err != nil {
			return structs.CommandResult{
				Output:    fmt.Sprintf("Failed to suspend process %d: %v", params.PID, err),
				Status:    "error",
				Completed: true,
			}
		}
		return structs.CommandResult{
			Output:    fmt.Sprintf("Process %d suspended (SIGSTOP). Use 'suspend -action resume -pid %d' to resume.", params.PID, params.PID),
			Status:    "success",
			Completed: true,
		}

	case "resume":
		err := syscall.Kill(params.PID, syscall.SIGCONT)
		if err != nil {
			return structs.CommandResult{
				Output:    fmt.Sprintf("Failed to resume process %d: %v", params.PID, err),
				Status:    "error",
				Completed: true,
			}
		}
		return structs.CommandResult{
			Output:    fmt.Sprintf("Process %d resumed (SIGCONT).", params.PID),
			Status:    "success",
			Completed: true,
		}

	default:
		return structs.CommandResult{
			Output:    fmt.Sprintf("Unknown action: %s. Use: suspend, resume", params.Action),
			Status:    "error",
			Completed: true,
		}
	}
}
