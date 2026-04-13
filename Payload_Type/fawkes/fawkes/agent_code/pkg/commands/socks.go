package commands

import (
	"fawkes/pkg/structs"
)

// SocksCommand implements the socks command
type SocksCommand struct{}

type socksArgs struct {
	Action string `json:"action"`
	Port   int    `json:"port"`
}

func (c *SocksCommand) Name() string {
	return "socks"
}

func (c *SocksCommand) Description() string {
	return "Start or stop a SOCKS5 proxy through this agent"
}

func (c *SocksCommand) Execute(task structs.Task) structs.CommandResult {
	params, parseErr := unmarshalParams[socksArgs](task)
	if parseErr != nil {
		return *parseErr
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
