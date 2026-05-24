package agentfunctions

import (
	"fmt"
	"strings"

	"github.com/MythicMeta/MythicContainer/logging"
	"github.com/MythicMeta/MythicContainer/mythicrpc"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddOnNewCallbackFunction(onNewCallback)
}

// onNewCallback is invoked by Mythic whenever a new Fawkes callback checks in.
// It auto-loads OS-appropriate commands that are marked CommandCanOnlyBeLoadedLater
// and logs the new callback event.
func onNewCallback(data agentstructs.PTOnNewCallbackAllData) agentstructs.PTOnNewCallbackResponse {
	response := agentstructs.PTOnNewCallbackResponse{
		AgentCallbackID: data.Callback.AgentCallbackID,
		Success:         true,
	}

	callbackOS := strings.ToLower(data.Callback.OS)
	callbackUser := data.Callback.User
	callbackHost := data.Callback.Host
	callbackIntegrity := data.Callback.IntegrityLevel

	logging.LogInfo("New Fawkes callback",
		"callback_id", data.Callback.AgentCallbackID,
		"display_id", data.Callback.DisplayID,
		"host", callbackHost,
		"user", callbackUser,
		"os", data.Callback.OS,
		"pid", data.Callback.PID,
		"integrity", callbackIntegrity,
		"process", data.Callback.ProcessName,
	)

	// Auto-load OS-specific commands that are CommandCanOnlyBeLoadedLater.
	// These are high-risk commands that shouldn't be loaded into every callback
	// but should be available when the operator needs them.
	var commandsToLoad []string

	if strings.Contains(callbackOS, "windows") {
		commandsToLoad = append(commandsToLoad, windowsAutoLoadCommands(callbackIntegrity)...)
	}
	if strings.Contains(callbackOS, "linux") {
		commandsToLoad = append(commandsToLoad, linuxAutoLoadCommands(callbackIntegrity)...)
	}
	if strings.Contains(callbackOS, "macos") || strings.Contains(callbackOS, "darwin") {
		commandsToLoad = append(commandsToLoad, macosAutoLoadCommands()...)
	}

	if len(commandsToLoad) > 0 {
		addResp, err := mythicrpc.SendMythicRPCCallbackAddCommand(mythicrpc.MythicRPCCallbackAddCommandMessage{
			AgentCallbackID: data.Callback.AgentCallbackID,
			Commands:        commandsToLoad,
		})
		if err != nil {
			logging.LogError(err, "Failed to auto-load commands", "callback_id", data.Callback.AgentCallbackID)
		} else if !addResp.Success {
			logging.LogError(nil, "Auto-load commands failed", "error", addResp.Error, "callback_id", data.Callback.AgentCallbackID)
		} else {
			logging.LogInfo("Auto-loaded commands",
				"callback_id", data.Callback.AgentCallbackID,
				"commands", strings.Join(commandsToLoad, ", "),
				"count", len(commandsToLoad),
			)
		}
	}

	// Update callback description with a summary tag line
	descParts := []string{}
	if callbackHost != "" {
		descParts = append(descParts, callbackHost)
	}
	if callbackUser != "" {
		descParts = append(descParts, callbackUser)
	}
	integrityStr := integrityLabel(callbackIntegrity)
	if integrityStr != "" {
		descParts = append(descParts, integrityStr)
	}

	if len(descParts) > 0 {
		desc := strings.Join(descParts, " | ")
		cbID := data.Callback.AgentCallbackID
		_, err := mythicrpc.SendMythicRPCCallbackUpdate(mythicrpc.MythicRPCCallbackUpdateMessage{
			AgentCallbackID: &cbID,
			Description:     &desc,
		})
		if err != nil {
			logging.LogError(err, "Failed to update callback description")
		}
	}

	return response
}

// windowsAutoLoadCommands returns commands to auto-load for Windows callbacks.
// Prioritizes by integrity level — elevated callbacks get credential dumping commands.
func windowsAutoLoadCommands(integrity int) []string {
	// Base commands always available via payload build; these are
	// "load later" commands useful for most Windows engagements.
	cmds := []string{
		"execute-memory",
		"execute-shellcode",
	}

	// Elevated callbacks (integrity >= 3 = admin, 4 = SYSTEM)
	if integrity >= 3 {
		cmds = append(cmds,
			"hashdump",
			"lsa-secrets",
			"getsystem",
		)
	}

	return cmds
}

// linuxAutoLoadCommands returns commands to auto-load for Linux callbacks.
func linuxAutoLoadCommands(integrity int) []string {
	cmds := []string{
		"execute-shellcode",
	}

	// Root callbacks
	if integrity >= 3 {
		cmds = append(cmds,
			"ptrace-inject",
		)
	}

	return cmds
}

// macosAutoLoadCommands returns commands to auto-load for macOS callbacks.
func macosAutoLoadCommands() []string {
	return []string{
		"execute-shellcode",
	}
}

// integrityLabel converts an integrity level number to a human-readable label.
func integrityLabel(level int) string {
	switch {
	case level >= 4:
		return "SYSTEM"
	case level >= 3:
		return "Admin"
	case level >= 2:
		return "Medium"
	default:
		return ""
	}
}

// logOperationEventForCallback creates an operation event log entry.
func logOperationEventForCallback(callbackID string, message string) {
	_, err := mythicrpc.SendMythicRPCOperationEventLogCreate(mythicrpc.MythicRPCOperationEventLogCreateMessage{
		Message: fmt.Sprintf("[CALLBACK] %s (callback: %s)", message, callbackID),
	})
	if err != nil {
		logging.LogError(err, "Failed to create operation event log")
	}
}
