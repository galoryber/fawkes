package agentfunctions

import (
	"fmt"
	"sort"

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

// getCallbackDomainList queries Mythic for unique domain names from active callbacks.
// Returns a sorted list of domains for commands that need domain context
// (make-token, runas, spray, cred-check).
func getCallbackDomainList(msg agentstructs.PTRPCDynamicQueryFunctionMessage) []string {
	var choices []string

	resp, err := mythicrpc.SendMythicRPCCallbackSearch(mythicrpc.MythicRPCCallbackSearchMessage{
		AgentCallbackID: msg.AgentCallbackID,
	})
	if err != nil {
		logging.LogError(err, "Failed to search callbacks for domain list")
		return choices
	}
	if !resp.Success {
		return choices
	}

	seen := make(map[string]bool)
	for _, cb := range resp.Results {
		if !cb.Active || cb.Domain == "" {
			continue
		}
		if !seen[cb.Domain] {
			seen[cb.Domain] = true
			choices = append(choices, cb.Domain)
		}
	}
	sort.Strings(choices)

	return choices
}

// getCallbackUserList queries Mythic for unique users from active callbacks.
// Returns "DOMAIN\user" strings for commands that need user context
// (make-token, runas, cred-check). Includes "." prefix for local users.
func getCallbackUserList(msg agentstructs.PTRPCDynamicQueryFunctionMessage) []string {
	var choices []string

	resp, err := mythicrpc.SendMythicRPCCallbackSearch(mythicrpc.MythicRPCCallbackSearchMessage{
		AgentCallbackID: msg.AgentCallbackID,
	})
	if err != nil {
		logging.LogError(err, "Failed to search callbacks for user list")
		return choices
	}
	if !resp.Success {
		return choices
	}

	seen := make(map[string]bool)
	for _, cb := range resp.Results {
		if !cb.Active || cb.User == "" {
			continue
		}
		user := cb.User
		if cb.Domain != "" {
			user = cb.Domain + "\\" + cb.User
		}
		if !seen[user] {
			seen[user] = true
			choices = append(choices, user)
		}
	}
	sort.Strings(choices)

	return choices
}

// getTokenUserList queries Mythic for unique users from tokens associated with the callback.
// Returns user strings from discovered/stolen tokens. Used for steal-token and
// make-token to suggest known user identities.
func getTokenUserList(msg agentstructs.PTRPCDynamicQueryFunctionMessage) []string {
	var choices []string

	callbackID := msg.Callback
	resp, err := mythicrpc.SendMythicRPCCallbackTokenSearch(mythicrpc.MythicRPCCallbackTokenSearchMessage{
		CallbackID: &callbackID,
	})
	if err != nil {
		logging.LogError(err, "Failed to search callback tokens for user list")
		return choices
	}
	if !resp.Success {
		return choices
	}

	seen := make(map[string]bool)
	for _, ct := range resp.CallbackTokens {
		if ct.Deleted {
			continue
		}
		user := ct.Token.User
		if user == "" {
			continue
		}
		label := fmt.Sprintf("%s (TokenID: %d, PID: %d)", user, ct.Token.TokenID, ct.Token.ProcessID)
		if !seen[label] {
			seen[label] = true
			choices = append(choices, label)
		}
	}

	return choices
}
