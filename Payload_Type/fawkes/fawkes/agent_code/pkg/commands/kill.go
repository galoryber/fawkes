package commands

import (
	"encoding/json"
	"fmt"
	"os"

	"fawkes/pkg/structs"
)

// KillCommand implements the kill command
type KillCommand struct{}

// Name returns the command name
func (c *KillCommand) Name() string {
	return "kill"
}

// Description returns the command description
func (c *KillCommand) Description() string {
	return "Terminate a process by PID"
}

// KillParams represents the JSON parameters
type KillParams struct {
	PID float64 `json:"pid"`
}

// Execute implements the Command interface
func (c *KillCommand) Execute(task structs.Task) structs.CommandResult {
	var params KillParams
	if err := json.Unmarshal([]byte(task.Params), &params); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error parsing parameters: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	pid := int(params.PID)
	if pid <= 0 {
		return structs.CommandResult{
			Output:    "Error: PID must be greater than 0",
			Status:    "error",
			Completed: true,
		}
	}

	proc, err := os.FindProcess(pid)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error finding process %d: %v", pid, err),
			Status:    "error",
			Completed: true,
		}
	}

	err = proc.Kill()
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error killing process %d: %v", pid, err),
			Status:    "error",
			Completed: true,
		}
	}

	return structs.CommandResult{
		Output:    fmt.Sprintf("Successfully terminated process %d", pid),
		Status:    "completed",
		Completed: true,
	}
}
