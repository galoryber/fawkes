package agentfunctions

import (
	"strings"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
	"github.com/MythicMeta/MythicContainer/logging"
	"github.com/MythicMeta/MythicContainer/mythicrpc"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "whoami",
		Description:         "Display current user identity and security context",
		HelpString:          "whoami",
		Version:             1,
		SupportedUIFeatures: []string{},
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1033"},
		ScriptOnlyCommand:   false,
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS:        []string{agentstructs.SUPPORTED_OS_LINUX, agentstructs.SUPPORTED_OS_MACOS, agentstructs.SUPPORTED_OS_WINDOWS},
			CommandIsSuggested: true,
		},
		CommandParameters:       []agentstructs.CommandParameter{},
		AssociatedBrowserScript: nil,
		TaskFunctionOPSECPre:    nil,
		TaskFunctionProcessResponse: func(processResponse agentstructs.PtTaskProcessResponseMessage) agentstructs.PTTaskProcessResponseMessageResponse {
			response := agentstructs.PTTaskProcessResponseMessageResponse{
				TaskID:  processResponse.TaskData.Task.ID,
				Success: true,
			}
			responseText, ok := processResponse.Response.(string)
			if !ok || responseText == "" {
				return response
			}
			update := mythicrpc.MythicRPCCallbackUpdateMessage{
				AgentCallbackID: &processResponse.TaskData.Callback.AgentCallbackID,
			}
			hasUpdate := false
			for _, line := range strings.Split(responseText, "\n") {
				trimmed := strings.TrimSpace(line)
				// Windows: "User:        DOMAIN\username"
				if val := extractField(trimmed, "User:"); val != "" {
					if parts := strings.SplitN(val, "\\", 2); len(parts) == 2 {
						update.Domain = &parts[0]
						update.User = &val
					} else {
						update.User = &val
					}
					hasUpdate = true
				}
				// Unix: "Host:     hostname"
				if val := extractField(trimmed, "Host:"); val != "" {
					update.Host = &val
					hasUpdate = true
				}
				// Windows: "Integrity:   High (S-1-16-...)"
				if val := extractField(trimmed, "Integrity:"); val != "" {
					level := parseIntegrityLevel(val)
					if level >= 0 {
						update.IntegrityLevel = &level
						hasUpdate = true
					}
				}
				// Unix: "Privilege: root"
				if val := extractField(trimmed, "Privilege:"); val != "" {
					if strings.Contains(val, "root") {
						level := 3 // High/root
						update.IntegrityLevel = &level
						hasUpdate = true
					}
				}
			}
			if hasUpdate {
				if _, err := mythicrpc.SendMythicRPCCallbackUpdate(update); err != nil {
					logging.LogError(err, "Failed to update callback metadata from whoami")
				}
			}
			return response
		},
		TaskFunctionCreateTasking: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  taskData.Task.ID,
			}
			return response
		},
	})
}

// parseIntegrityLevel converts a text integrity level to Mythic's numeric value.
func parseIntegrityLevel(val string) int {
	lower := strings.ToLower(val)
	switch {
	case strings.HasPrefix(lower, "system"):
		return 4
	case strings.HasPrefix(lower, "high"):
		return 3
	case strings.HasPrefix(lower, "medium"):
		return 2
	case strings.HasPrefix(lower, "low"):
		return 1
	case strings.HasPrefix(lower, "untrusted"):
		return 0
	default:
		return -1
	}
}
