package agentfunctions

import (
	"fmt"
	"strings"

	"github.com/MythicMeta/MythicContainer/logging"
	"github.com/MythicMeta/MythicContainer/mythicrpc"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "steal-token",
		Description:         "Steal and impersonate a token from another process",
		HelpString:          "steal-token <PID>",
		Version:             1,
		SupportedUIFeatures: []string{},
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1134.001"},
		ScriptOnlyCommand:   false,
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_WINDOWS},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:                                    "pid",
				ModalDisplayName:                        "Process ID",
				CLIName:                                 "pid",
				ParameterType:                           agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				Description:                             "Process ID to steal token from (e.g., lsass.exe, winlogon.exe)",
				Choices:                                 []string{},
				DefaultValue:                            0,
				SupportedAgents:                         []string{},
				ChoicesAreAllCommands:                   false,
				ChoicesAreLoadedCommands:                false,
				FilterCommandChoicesByCommandAttributes: map[string]string{},
				DynamicQueryFunction:                    nil,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: true,
						UIModalPosition:     1,
						GroupName:           "Default",
					},
				},
			},
		},
		AssociatedBrowserScript: nil,
		TaskFunctionOPSECPre: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTTaskOPSECPreTaskMessageResponse {
				pid, _ := taskData.Args.GetStringArg("pid")
				return agentstructs.PTTTaskOPSECPreTaskMessageResponse{
					TaskID:             taskData.Task.ID,
					Success:            true,
					OpsecPreBlocked:    false,
					OpsecPreMessage:    fmt.Sprintf("OPSEC WARNING: Stealing token from PID %s. Opens target process with TOKEN_DUPLICATE access and impersonates its security context. Generates Event ID 4624 (impersonation logon) and may trigger EDR process access monitoring.", pid),
					OpsecPreBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
				}
			},
		TaskFunctionOPSECPost: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskOPSECPostTaskMessageResponse {
			pid, _ := taskData.Args.GetStringArg("pid")
			return agentstructs.PTTaskOPSECPostTaskMessageResponse{
				TaskID:              taskData.Task.ID,
				Success:             true,
				OpsecPostBlocked:    false,
				OpsecPostMessage:    fmt.Sprintf("OPSEC AUDIT: Token stolen from PID %s. Cleanup: use 'rev2self' to revert to original token. The stolen token handle remains open until reverted. Check Event ID 4624/4634 for impersonation evidence.", pid),
				OpsecPostBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionParseArgString: func(args *agentstructs.PTTaskMessageArgsData, input string) error {
			if input == "" {
				return nil
			}
			return args.LoadArgsFromJSONString(input)
		},
		TaskFunctionParseArgDictionary: func(args *agentstructs.PTTaskMessageArgsData, input map[string]interface{}) error {
			return args.LoadArgsFromDictionary(input)
		},
		TaskFunctionCreateTasking: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  taskData.Task.ID,
			}
			pid, _ := taskData.Args.GetNumberArg("pid")
			display := fmt.Sprintf("PID: %d", int(pid))
			response.DisplayParams = &display
			createArtifact(taskData.Task.ID, "Token Steal", fmt.Sprintf("OpenProcess + OpenProcessToken + DuplicateTokenEx on PID %d", int(pid)))
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

			// Only track on successful steal (output contains "New:")
			if !strings.Contains(responseText, "New:") {
				return response
			}

			// Parse "New: DOMAIN\user" from output
			user := ""
			for _, line := range strings.Split(responseText, "\n") {
				if strings.HasPrefix(strings.TrimSpace(line), "New:") {
					user = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "New:"))
					break
				}
			}
			if user == "" {
				return response
			}

			// Get source PID for context
			pid, _ := processResponse.TaskData.Args.GetNumberArg("pid")

			// Register token with Mythic's callback token tracker
			host := processResponse.TaskData.Callback.Host
			_, err := mythicrpc.SendMythicRPCCallbackTokenCreate(mythicrpc.MythicRPCCallbackTokenCreateMessage{
				TaskID: processResponse.TaskData.Task.ID,
				CallbackTokens: []mythicrpc.MythicRPCCallbackTokenData{
					{
						Action:  "add",
						Host:    &host,
						TokenID: uint64(processResponse.TaskData.Task.ID),
						TokenInfo: &mythicrpc.MythicRPCTokenCreateTokenData{
							User:      user,
							ProcessID: int(pid),
						},
					},
				},
			})
			if err != nil {
				logging.LogError(err, "Failed to register stolen token with Mythic", "user", user, "pid", int(pid))
			}

			// Tag elevated access
			if strings.Contains(strings.ToUpper(user), "SYSTEM") {
				tagTask(processResponse.TaskData.Task.ID, "SYSTEM",
					fmt.Sprintf("Stole SYSTEM token from PID %d", int(pid)))
			} else {
				tagTask(processResponse.TaskData.Task.ID, "ELEVATED",
					fmt.Sprintf("Stole token: %s (PID %d)", user, int(pid)))
			}

			return response
		},
	})
}
