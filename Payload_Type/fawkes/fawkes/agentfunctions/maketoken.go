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
		Name:                "make-token",
		Description:         "Create a token from credentials and impersonate it, or spawn a process with it",
		HelpString:          "make-token -username <user> -domain <domain> -password <pass> [-action spawn -command <cmd>]",
		Version:             2,
		SupportedUIFeatures: []string{},
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1134.001", "T1134.002"},
		ScriptOnlyCommand:   false,
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_WINDOWS},
			FilterCommandAvailabilityByAgentBuildParameters: map[string]string{"selected_os": "Windows"},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:                                    "action",
				ModalDisplayName:                        "Action",
				CLIName:                                 "action",
				ParameterType:                           agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Description:                             "impersonate: create token and impersonate (default). spawn: create token and launch a process with it.",
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
				Name:                                    "username",
				ModalDisplayName:                        "Username",
				CLIName:                                 "username",
				ParameterType:                           agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:                             "Username to create token for",
				Choices:                                 []string{},
				DefaultValue:                            "",
				SupportedAgents:                         []string{},
				ChoicesAreAllCommands:                   false,
				ChoicesAreLoadedCommands:                false,
				FilterCommandChoicesByCommandAttributes: map[string]string{},
				DynamicQueryFunction:                    getCallbackUserList,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: true,
						UIModalPosition:     2,
						GroupName:            "Default",
					},
				},
			},
			{
				Name:                                    "domain",
				ModalDisplayName:                        "Domain",
				CLIName:                                 "domain",
				ParameterType:                           agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:                             "Domain for the user (use '.' for local)",
				Choices:                                 []string{},
				DefaultValue:                            ".",
				SupportedAgents:                         []string{},
				ChoicesAreAllCommands:                   false,
				ChoicesAreLoadedCommands:                false,
				FilterCommandChoicesByCommandAttributes: map[string]string{},
				DynamicQueryFunction:                    getCallbackDomainList,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     3,
						GroupName:            "Default",
					},
				},
			},
			{
				Name:                                    "password",
				ModalDisplayName:                        "Password",
				CLIName:                                 "password",
				ParameterType:                           agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:                             "Password for the user",
				Choices:                                 []string{},
				DefaultValue:                            "",
				SupportedAgents:                         []string{},
				ChoicesAreAllCommands:                   false,
				ChoicesAreLoadedCommands:                false,
				FilterCommandChoicesByCommandAttributes: map[string]string{},
				DynamicQueryFunction:                    nil,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: true,
						UIModalPosition:     4,
						GroupName:            "Default",
					},
				},
			},
			{
				Name:                                    "logon_type",
				ModalDisplayName:                        "Logon Type",
				CLIName:                                 "logon_type",
				ParameterType:                           agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				Description:                             "Type of logon: 2=Interactive, 3=Network, 9=NewCredentials (default). For spawn, type 2 (Interactive) creates a full logon session.",
				Choices:                                 []string{},
				DefaultValue:                            9,
				SupportedAgents:                         []string{},
				ChoicesAreAllCommands:                   false,
				ChoicesAreLoadedCommands:                false,
				FilterCommandChoicesByCommandAttributes: map[string]string{},
				DynamicQueryFunction:                    nil,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     5,
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
						UIModalPosition:     6,
						GroupName:            "Default",
					},
				},
			},
		},
		AssociatedBrowserScript: nil,
		TaskFunctionOPSECPre: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTTaskOPSECPreTaskMessageResponse {
			action, _ := taskData.Args.GetStringArg("action")
			username, _ := taskData.Args.GetStringArg("username")
			domain, _ := taskData.Args.GetStringArg("domain")

			msg := fmt.Sprintf("OPSEC WARNING: Creating token for %s\\%s via LogonUserW.", domain, username)
			if action == "spawn" {
				command, _ := taskData.Args.GetStringArg("command")
				msg += fmt.Sprintf(" Spawning process '%s' with forged token via CreateProcessWithTokenW.", command)
				msg += " Generates Event ID 4624 (logon) + Event ID 4688 (process creation). EDR monitors token-based process creation."
			} else {
				msg += " Generates Event ID 4624 (logon type 9 — NewCredentials). The new token will be used for subsequent network operations. Failed attempts generate Event ID 4625."
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
			username, _ := taskData.Args.GetStringArg("username")
			domain, _ := taskData.Args.GetStringArg("domain")

			msg := fmt.Sprintf("OPSEC AUDIT: Token created for %s\\%s.", domain, username)
			if action == "spawn" {
				msg += " Spawned process runs under forged token. Kill the spawned process to clean up. Check Event ID 4688 for process creation evidence."
			} else {
				msg += " Cleanup: use 'rev2self' to drop impersonated token. Check Event ID 4624/4634 for logon/logoff evidence."
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
			username, _ := taskData.Args.GetStringArg("username")
			domain, _ := taskData.Args.GetStringArg("domain")

			if action == "spawn" {
				command, _ := taskData.Args.GetStringArg("command")
				display := fmt.Sprintf("spawn %s\\%s → %s", domain, username, command)
				response.DisplayParams = &display
				createArtifact(taskData.Task.ID, "Token Spawn",
					fmt.Sprintf("LogonUserW %s\\%s, CreateProcessWithTokenW: %s", domain, username, command))
				logOperationEvent(taskData.Task.ID,
					fmt.Sprintf("[TOKEN SPAWN] Creating process as %s\\%s: %s", domain, username, command), false)
			} else {
				display := fmt.Sprintf("%s\\%s", domain, username)
				response.DisplayParams = &display
				createArtifact(taskData.Task.ID, "Logon",
					fmt.Sprintf("LogonUserW %s\\%s (type 9)", domain, username))
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

			if action == "spawn" {
				// Track spawn success as process creation artifact
				if strings.Contains(responseText, "New PID:") {
					username, _ := processResponse.TaskData.Args.GetStringArg("username")
					domain, _ := processResponse.TaskData.Args.GetStringArg("domain")
					user := fmt.Sprintf("%s\\%s", domain, username)

					createArtifact(processResponse.TaskData.Task.ID, "Process Created",
						fmt.Sprintf("CreateProcessWithTokenW as %s", user))
				}
				return response
			}

			// Original impersonate behavior: track token
			if !strings.Contains(responseText, "Successfully impersonated") && !strings.Contains(responseText, "New:") {
				return response
			}

			username, _ := processResponse.TaskData.Args.GetStringArg("username")
			domain, _ := processResponse.TaskData.Args.GetStringArg("domain")
			user := fmt.Sprintf("%s\\%s", domain, username)

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
							User: user,
						},
					},
				},
			})
			if err != nil {
				logging.LogError(err, "Failed to register token with Mythic", "user", user)
			}

			return response
		},
	})
}
