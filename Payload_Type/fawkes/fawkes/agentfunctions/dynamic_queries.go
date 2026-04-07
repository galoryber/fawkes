package agentfunctions

import (
	"fmt"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
	"github.com/MythicMeta/MythicContainer/logging"
	"github.com/MythicMeta/MythicContainer/mythicrpc"
)

// getCallbackList queries Mythic for active callbacks in the same operation.
// Returns display strings like "host (user@process #ID)" for operator selection.
// Used as DynamicQueryFunction for commands that target other callbacks (link, etc.).
func getCallbackList(msg agentstructs.PTRPCDynamicQueryFunctionMessage) []string {
	var choices []string

	resp, err := mythicrpc.SendMythicRPCCallbackSearch(mythicrpc.MythicRPCCallbackSearchMessage{
		AgentCallbackID: msg.AgentCallbackID,
	})
	if err != nil {
		logging.LogError(err, "Failed to search callbacks for dynamic query")
		return choices
	}
	if !resp.Success {
		logging.LogError(nil, "Callback search failed", "error", resp.Error)
		return choices
	}

	for _, cb := range resp.Results {
		if !cb.Active {
			continue
		}
		// Skip the current callback (can't link to yourself)
		if cb.AgentCallbackID == msg.AgentCallbackID {
			continue
		}
		label := fmt.Sprintf("%s (%s@%s #%d)", cb.Host, cb.User, cb.ProcessName, cb.DisplayID)
		choices = append(choices, label)
	}

	return choices
}

// getActiveHostList queries Mythic for unique hostnames from active callbacks.
// Returns a list of host IPs/names for commands that target remote hosts.
// Used as DynamicQueryFunction for lateral movement commands (psexec, wmi, dcom, etc.).
func getActiveHostList(msg agentstructs.PTRPCDynamicQueryFunctionMessage) []string {
	var choices []string

	resp, err := mythicrpc.SendMythicRPCCallbackSearch(mythicrpc.MythicRPCCallbackSearchMessage{
		AgentCallbackID: msg.AgentCallbackID,
	})
	if err != nil {
		logging.LogError(err, "Failed to search callbacks for host list")
		return choices
	}
	if !resp.Success {
		return choices
	}

	seen := make(map[string]bool)
	for _, cb := range resp.Results {
		if !cb.Active {
			continue
		}
		if cb.Host != "" && !seen[cb.Host] {
			seen[cb.Host] = true
			choices = append(choices, cb.Host)
		}
		if cb.Ip != "" && !seen[cb.Ip] {
			seen[cb.Ip] = true
			choices = append(choices, cb.Ip)
		}
	}

	return choices
}
