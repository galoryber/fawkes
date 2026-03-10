//go:build !windows
// +build !windows

package commands

import (
	"encoding/json"
	"os"

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
	var params KillParams
	if err := json.Unmarshal([]byte(task.Params), &params); err != nil {
		return errorf("Error parsing parameters: %v", err)
	}

	pid := params.PID
	if pid <= 0 {
		return errorResult("Error: PID must be greater than 0")
	}

	proc, err := os.FindProcess(pid)
	if err != nil {
		return errorf("Error finding process %d: %v", pid, err)
	}

	err = proc.Kill()
	if err != nil {
		return errorf("Error killing process %d: %v", pid, err)
	}

	return successf("Successfully terminated process %d", pid)
}
