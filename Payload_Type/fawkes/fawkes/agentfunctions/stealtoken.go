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
		Description:         "Steal and impersonate a token from another process, or spawn a process with a stolen token",
		HelpString:          "steal-token -pid <PID> [-action spawn -command <cmd>]",
		Version:             2,
		SupportedUIFeatures: []string{},
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1134.001", "T1134.002"},
		ScriptOnlyCommand:   false,
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_WINDOWS},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:                                    "action",
				ModalDisplayName:                        "Action",
				CLIName:                                 "action",
				ParameterType:                           agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Description:                             "impersonate: steal token and impersonate (default). spawn: steal token and create a process with it.",
				Choices:                                 []string{"impersonate", "spawn"},
				DefaultValue:                            "impersonate",
				SupportedAgents:                         []string{},
				ChoicesAreAllCommands:                   false,
				ChoicesAreLoadedCommands:                false,
				FilterCommandChoicesByCommandAttributes: map[string]string{},
				DynamicQueryFunction:                    nil,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     1,
						GroupName:            "Default",
					},
				},
			},
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
						UIModalPosition:     2,
						GroupName:            "Default",
					},
				},
			},
			{
				Name:                                    "command",
				ModalDisplayName:                        "Command Line",
				CLIName:                                 "command",
				ParameterType:                           agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:                             "Command line to execute when action=spawn (e.g., cmd.exe /c whoami, or path to payload)",
				Choices:                                 []string{},
				DefaultValue:                            "",
				SupportedAgents:                         []string{},
				ChoicesAreAllCommands:                   false,
				ChoicesAreLoadedCommands:                false,
				FilterCommandChoicesByCommandAttributes: map[string]string{},
				DynamicQueryFunction:                    nil,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     3,
						GroupName:            "Default",
					},
				},
			},
		},
		AssociatedBrowserScript: nil,
		TaskFunctionOPSECPre: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTTaskOPSECPreTaskMessageResponse {
			action, _ := taskData.Args.GetStringArg("action")
			pid, _ := taskData.Args.GetStringArg("pid")

			msg := fmt.Sprintf("OPSEC WARNING: Stealing token from PID %s. Opens target process with TOKEN_DUPLICATE access.", pid)
			if action == "spawn" {
				command, _ := taskData.Args.GetStringArg("command")
				msg += fmt.Sprintf(" Spawning process '%s' with stolen token via CreateProcessWithTokenW.", command)
				msg += " Generates Event ID 4624 (logon) and Event ID 4688 (process creation). EDR monitors cross-process token theft + child process creation."
			} else {
				msg += " Impersonates the stolen security context. Generates Event ID 4624 (impersonation logon) and may trigger EDR process access monitoring."
			}

			return agentstructs.PTTTaskOPSECPreTaskMessageResponse{
				TaskID:             taskData.Task.ID,
				Success:            true,
				OpsecPreBlocked:    false,
				OpsecPreMessage:    msg,
				OpsecPreBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionOPSECPost: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskOPSECPostTaskMessageResponse {
			action, _ := taskData.Args.GetStringArg("action")
			pid, _ := taskData.Args.GetStringArg("pid")

			msg := fmt.Sprintf("OPSEC AUDIT: Token stolen from PID %s.", pid)
			if action == "spawn" {
				msg += " Spawned process runs under stolen token. Kill the spawned process to clean up. Check Event ID 4688 for process creation evidence."
			} else {
				msg += " Cleanup: use 'rev2self' to revert to original token. The stolen token handle remains open until reverted. Check Event ID 4624/4634 for impersonation evidence."
			}

			return agentstructs.PTTaskOPSECPostTaskMessageResponse{
				TaskID:              taskData.Task.ID,
				Success:             true,
				OpsecPostBlocked:    false,
				OpsecPostMessage:    msg,
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
			action, _ := taskData.Args.GetStringArg("action")
			pid, _ := taskData.Args.GetNumberArg("pid")

			if action == "spawn" {
				command, _ := taskData.Args.GetStringArg("command")
				display := fmt.Sprintf("spawn PID:%d → %s", int(pid), command)
				response.DisplayParams = &display
				createArtifact(taskData.Task.ID, "Token Spawn",
					fmt.Sprintf("OpenProcess + OpenProcessToken + DuplicateTokenEx on PID %d, CreateProcessWithTokenW: %s", int(pid), command))
			} else {
				display := fmt.Sprintf("PID: %d", int(pid))
				response.DisplayParams = &display
				createArtifact(taskData.Task.ID, "Token Steal",
					fmt.Sprintf("OpenProcess + OpenProcessToken + DuplicateTokenEx on PID %d", int(pid)))
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

			action, _ := processResponse.TaskData.Args.GetStringArg("action")
			pid, _ := processResponse.TaskData.Args.GetNumberArg("pid")

			if action == "spawn" {
				// Track spawn as process creation + operation event
				if strings.Contains(responseText, "New PID:") {
					// Extract identity from "Token identity: DOMAIN\user" or "Spawned process as DOMAIN\user"
					user := ""
					for _, line := range strings.Split(responseText, "\n") {
						trimmed := strings.TrimSpace(line)
						if strings.HasPrefix(trimmed, "Token identity:") {
							user = strings.TrimSpace(strings.TrimPrefix(trimmed, "Token identity:"))
						} else if strings.HasPrefix(trimmed, "Spawned process as") {
							user = strings.TrimSpace(strings.TrimPrefix(trimmed, "Spawned process as"))
						}
					}

					logOperationEvent(processResponse.TaskData.Task.ID,
						fmt.Sprintf("[TOKEN SPAWN] Created process with stolen token from PID %d as %s", int(pid), user), false)

					createArtifact(processResponse.TaskData.Task.ID, "Process Created",
						fmt.Sprintf("CreateProcessWithTokenW with token from PID %d (user: %s)", int(pid), user))
				}
				return response
			}

			// Original impersonate behavior: track token
			if !strings.Contains(responseText, "New:") {
				return response
			}

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
