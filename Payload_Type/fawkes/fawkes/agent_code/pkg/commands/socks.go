package commands

import (
	"encoding/json"
	"fmt"

	"fawkes/pkg/structs"
)

// SocksCommand implements the socks command
type SocksCommand struct{}

func (c *SocksCommand) Name() string {
	return "socks"
}

func (c *SocksCommand) Description() string {
	return "Start or stop a SOCKS5 proxy through this agent"
}

func (c *SocksCommand) Execute(task structs.Task) structs.CommandResult {
	var params struct {
		Action string `json:"action"`
		Port   int    `json:"port"`
	}

	if err := json.Unmarshal([]byte(task.Params), &params); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Failed to parse parameters: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	switch params.Action {
	case "start":
		return structs.CommandResult{
			Output:    fmt.Sprintf("[+] SOCKS5 proxy active on Mythic port %d. Agent is processing proxy traffic.", params.Port),
			Status:    "completed",
			Completed: true,
		}
	case "stop":
		return structs.CommandResult{
			Output:    fmt.Sprintf("[+] SOCKS5 proxy on port %d stopped.", params.Port),
			Status:    "completed",
			Completed: true,
		}
	default:
		return structs.CommandResult{
			Output:    fmt.Sprintf("Unknown action: %s (use 'start' or 'stop')", params.Action),
			Status:    "error",
			Completed: true,
		}
	}
}
