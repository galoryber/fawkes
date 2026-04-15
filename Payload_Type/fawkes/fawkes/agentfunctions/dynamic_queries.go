package agentfunctions

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

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

// getProcessList queries the Mythic process browser for processes on the callback's host.
// Returns "PID - Name (User)" formatted strings for PID parameter autocomplete.
// Requires the operator to have run "ps" at least once to populate the process browser.
func getProcessList(msg agentstructs.PTRPCDynamicQueryFunctionMessage) []string {
	var choices []string

	// Get the callback's host from callback search
	cbResp, err := mythicrpc.SendMythicRPCCallbackSearch(mythicrpc.MythicRPCCallbackSearchMessage{
		AgentCallbackID: msg.AgentCallbackID,
	})
	if err != nil || !cbResp.Success || len(cbResp.Results) == 0 {
		return choices
	}

	// Find the current callback's host
	var host string
	for _, cb := range cbResp.Results {
		if cb.AgentCallbackID == msg.AgentCallbackID {
			host = cb.Host
			break
		}
	}

	// Find any task on this callback to use as context for process search
	callbackID := msg.Callback
	taskResp, err := mythicrpc.SendMythicRPCTaskSearch(mythicrpc.MythicRPCTaskSearchMessage{
		SearchCallbackID: &callbackID,
	})
	if err != nil || !taskResp.Success || len(taskResp.Tasks) == 0 {
		return choices
	}

	// Use the first task's ID for process search context
	processResp, err := mythicrpc.SendMythicRPCProcessSearch(mythicrpc.MythicRPCProcessSearchMessage{
		TaskID: taskResp.Tasks[0].ID,
		SearchProcess: mythicrpc.MythicRPCProcessSearchProcessData{
			Host: &host,
		},
	})
	if err != nil || !processResp.Success {
		return choices
	}

	// Format: "PID - Name (User)" — sorted by PID
	type procEntry struct {
		pid   int
		label string
	}
	var entries []procEntry
	seen := make(map[int]bool)
	for _, p := range processResp.Processes {
		pid := 0
		if p.ProcessID != nil {
			pid = *p.ProcessID
		}
		if pid <= 0 || seen[pid] {
			continue
		}
		seen[pid] = true

		name := "<unknown>"
		if p.Name != nil && *p.Name != "" {
			name = *p.Name
		}
		user := ""
		if p.User != nil && *p.User != "" {
			user = *p.User
		}

		var label string
		if user != "" {
			label = fmt.Sprintf("%d - %s (%s)", pid, name, user)
		} else {
			label = fmt.Sprintf("%d - %s", pid, name)
		}
		entries = append(entries, procEntry{pid: pid, label: label})
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].pid < entries[j].pid
	})

	for _, e := range entries {
		choices = append(choices, e.label)
	}
	return choices
}

// parsePIDFromArg extracts a PID from a task's "pid" argument, handling both numeric
// values (direct input) and DQF-formatted strings like "1234 - notepad.exe (SYSTEM)".
// After parsing, it sets the arg back to an int so the agent receives a numeric value.
func parsePIDFromArg(taskData *agentstructs.PTTaskMessageAllData) (int, error) {
	// Try as number first (backward compat, CLI, numeric input)
	if pid, err := taskData.Args.GetNumberArg("pid"); err == nil {
		return int(pid), nil
	}

	// Try as string (DQF dropdown selection or typed string)
	pidStr, err := taskData.Args.GetStringArg("pid")
	if err != nil || pidStr == "" {
		// Set as int so agent receives numeric 0, not empty string
		_ = taskData.Args.SetArgValue("pid", 0)
		return 0, fmt.Errorf("pid parameter not found")
	}

	// Extract number before " - " if DQF format ("1234 - notepad.exe (SYSTEM)")
	if idx := strings.Index(pidStr, " - "); idx > 0 {
		pidStr = pidStr[:idx]
	}
	pidStr = strings.TrimSpace(pidStr)

	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		_ = taskData.Args.SetArgValue("pid", 0)
		return 0, fmt.Errorf("invalid PID value: %s", pidStr)
	}

	// Set back as int so the agent receives a numeric value in JSON
	_ = taskData.Args.SetArgValue("pid", pid)
	return pid, nil
}
