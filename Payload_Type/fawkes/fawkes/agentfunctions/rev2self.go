package agentfunctions

import (
	"strings"

	"github.com/MythicMeta/MythicContainer/logging"
	"github.com/MythicMeta/MythicContainer/mythicrpc"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "rev2self",
		Description:         "Revert to original security context (drop impersonation)",
		HelpString:          "rev2self",
		Version:             1,
		SupportedUIFeatures: []string{},
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1134.001"},
		ScriptOnlyCommand:   false,
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_WINDOWS},
		},
		CommandParameters:       []agentstructs.CommandParameter{},
		AssociatedBrowserScript: nil,
		TaskFunctionOPSECPre: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTTaskOPSECPreTaskMessageResponse {
				return agentstructs.PTTTaskOPSECPreTaskMessageResponse{
					TaskID:             taskData.Task.ID,
					Success:            true,
					OpsecPreBlocked:    false,
					OpsecPreMessage:    "OPSEC WARNING: Reverting to original security context (rev2self). Drops current impersonation token and restores the process token. Generates Event ID 4624 (logon) with the original identity.",
					OpsecPreBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
				}
			},
		TaskFunctionOPSECPost: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskOPSECPostTaskMessageResponse {
			return agentstructs.PTTaskOPSECPostTaskMessageResponse{
				TaskID:              taskData.Task.ID,
				Success:             true,
				OpsecPostBlocked:    false,
				OpsecPostMessage:    "OPSEC AUDIT: Token reverted to original identity. Previous impersonation token handle closed. Verify with 'whoami' that identity matches expected context.",
				OpsecPostBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionCreateTasking: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  taskData.Task.ID,
			}
			return response
		},
		TaskFunctionProcessResponse: func(processResponse agentstructs.PtTaskProcessResponseMessage) agentstructs.PTTaskProcessResponseMessageResponse {
			response := agentstructs.PTTaskProcessResponseMessageResponse{
				TaskID:  processResponse.TaskData.Task.ID,
				Success: true,
			}

			responseText, ok := processResponse.Response.(string)
			if !ok || responseText == "" {
				return response
			}

			// Only remove tokens on successful reversion (output contains "Reverted to:")
			if !strings.Contains(responseText, "Reverted to:") {
				return response
			}

			// Remove all tokens from callback token tracker
			host := processResponse.TaskData.Callback.Host
			_, err := mythicrpc.SendMythicRPCCallbackTokenRemove(mythicrpc.MythicRPCCallbackTokenRemoveMessage{
				TaskID: processResponse.TaskData.Task.ID,
				CallbackTokens: []mythicrpc.MythicRPCCallbackTokenRemoveCallbackTokenData{
					{
						Action: "remove",
						Host:   &host,
					},
				},
			})
			if err != nil {
				logging.LogError(err, "Failed to remove tokens from Mythic tracker on rev2self")
			}

			return response
		},
	})
}
