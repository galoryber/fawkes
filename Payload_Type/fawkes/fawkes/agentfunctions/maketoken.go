package agentfunctions

import (
	"encoding/json"
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
				Description:                             "impersonate: create token and impersonate (default). spawn: create token and launch a process with it. auto-verify: impersonate then auto-run whoami + getprivs to verify.",
				Choices:                                 []string{"impersonate", "spawn", "auto-verify"},
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
			TaskCompletionFunctions: map[string]agentstructs.PTTaskCompletionFunction{
				"maketokenAutoVerifyDone":   maketokenAutoVerifyDone,
				"maketokenAutoWhoamiDone":   maketokenAutoWhoamiDone,
				"maketokenAutoGetprivsDone": maketokenAutoGetprivsDone,
			},
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

			if action == "auto-verify" {
				display := fmt.Sprintf("auto-verify: make-token %s\\%s \u2192 whoami \u2192 getprivs", domain, username)
				response.DisplayParams = &display

				// Build impersonate params from current args
				password, _ := taskData.Args.GetStringArg("password")
				logonType, _ := taskData.Args.GetNumberArg("logon_type")
				subtaskParams, _ := json.Marshal(map[string]interface{}{
					"action": "impersonate", "username": username,
					"domain": domain, "password": password, "logon_type": logonType,
				})

				callbackFunc := "maketokenAutoVerifyDone"
				_, err := mythicrpc.SendMythicRPCTaskCreateSubtask(mythicrpc.MythicRPCTaskCreateSubtaskMessage{
					TaskID:                  taskData.Task.ID,
					SubtaskCallbackFunction: &callbackFunc,
					CommandName:             "make-token",
					Params:                  string(subtaskParams),
				})
				if err != nil {
					response.Success = false
					response.Error = fmt.Sprintf("Failed to start auto-verify chain: %v", err)
					return response
				}
				createArtifact(taskData.Task.ID, "Subtask Chain",
					fmt.Sprintf("Token auto-verify: make-token %s\\%s \u2192 whoami \u2192 getprivs", domain, username))
				logOperationEvent(taskData.Task.ID,
					fmt.Sprintf("[TOKEN] Auto-verify chain started for %s\\%s", domain, username), false)
				return response
			}

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

// --- make-token auto-verify subtask chain ---

// Step 1: make-token done → run whoami to verify identity
func maketokenAutoVerifyDone(
	taskData *agentstructs.PTTaskMessageAllData,
	subtaskData *agentstructs.PTTaskMessageAllData,
	_ *agentstructs.SubtaskGroupName,
) agentstructs.PTTaskCompletionFunctionMessageResponse {
	response := agentstructs.PTTaskCompletionFunctionMessageResponse{
		TaskID:  taskData.Task.ID,
		Success: true,
	}

	responseText := getSubtaskResponses(subtaskData.Task.ID)
	if subtaskData.Task.Status == "error" {
		completed := true
		response.Completed = &completed
		msg := fmt.Sprintf("Auto-verify: make-token failed: %s", responseText)
		response.Stderr = &msg
		mythicrpc.SendMythicRPCResponseCreate(mythicrpc.MythicRPCResponseCreateMessage{
			TaskID: taskData.Task.ID, Response: []byte(msg),
		})
		return response
	}

	mythicrpc.SendMythicRPCResponseCreate(mythicrpc.MythicRPCResponseCreateMessage{
		TaskID:   taskData.Task.ID,
		Response: []byte(fmt.Sprintf("[Step 1/3] Token created. %s Verifying identity...", strings.TrimSpace(responseText))),
	})

	callbackFunc := "maketokenAutoWhoamiDone"
	if _, err := mythicrpc.SendMythicRPCTaskCreateSubtask(mythicrpc.MythicRPCTaskCreateSubtaskMessage{
		TaskID: taskData.Task.ID, SubtaskCallbackFunction: &callbackFunc,
		CommandName: "whoami", Params: `{}`,
	}); err != nil {
		completed := true
		response.Completed = &completed
		msg := fmt.Sprintf("Auto-verify: token created but whoami failed: %s", err.Error())
		response.Stderr = &msg
	}
	return response
}

// Step 2: whoami done → run getprivs
func maketokenAutoWhoamiDone(
	taskData *agentstructs.PTTaskMessageAllData,
	subtaskData *agentstructs.PTTaskMessageAllData,
	_ *agentstructs.SubtaskGroupName,
) agentstructs.PTTaskCompletionFunctionMessageResponse {
	response := agentstructs.PTTaskCompletionFunctionMessageResponse{
		TaskID:  taskData.Task.ID,
		Success: true,
	}

	responseText := getSubtaskResponses(subtaskData.Task.ID)
	mythicrpc.SendMythicRPCResponseCreate(mythicrpc.MythicRPCResponseCreateMessage{
		TaskID:   taskData.Task.ID,
		Response: []byte(fmt.Sprintf("[Step 2/3] Identity verified: %s. Checking privileges...", strings.TrimSpace(responseText))),
	})

	callbackFunc := "maketokenAutoGetprivsDone"
	if _, err := mythicrpc.SendMythicRPCTaskCreateSubtask(mythicrpc.MythicRPCTaskCreateSubtaskMessage{
		TaskID: taskData.Task.ID, SubtaskCallbackFunction: &callbackFunc,
		CommandName: "getprivs", Params: `{}`,
	}); err != nil {
		completed := true
		response.Completed = &completed
		msg := fmt.Sprintf("Auto-verify: identity confirmed but getprivs failed: %s", err.Error())
		response.Stderr = &msg
	}
	return response
}

// Step 3 (Final): getprivs done → aggregate and complete
func maketokenAutoGetprivsDone(
	taskData *agentstructs.PTTaskMessageAllData,
	subtaskData *agentstructs.PTTaskMessageAllData,
	_ *agentstructs.SubtaskGroupName,
) agentstructs.PTTaskCompletionFunctionMessageResponse {
	response := agentstructs.PTTaskCompletionFunctionMessageResponse{
		TaskID:  taskData.Task.ID,
		Success: true,
	}

	responseText := getSubtaskResponses(subtaskData.Task.ID)
	privCount := strings.Count(responseText, "\n")

	// Aggregate chain results
	parentID := taskData.Task.ID
	summary := "=== Make-Token Auto-Verify Complete ===\n"
	searchResult, err := mythicrpc.SendMythicRPCTaskSearch(mythicrpc.MythicRPCTaskSearchMessage{
		TaskID: parentID, SearchParentTaskID: &parentID,
	})
	if err == nil && searchResult.Success {
		for _, task := range searchResult.Tasks {
			status := "\u2713"
			if task.Status == "error" {
				status = "\u2717"
			}
			summary += fmt.Sprintf("  %s %s %s\n", status, task.CommandName, task.DisplayParams)
		}
	}
	summary += fmt.Sprintf("\nPrivileges: %d available\n", privCount)

	completed := true
	response.Completed = &completed
	response.Stdout = &summary

	mythicrpc.SendMythicRPCResponseCreate(mythicrpc.MythicRPCResponseCreateMessage{
		TaskID: taskData.Task.ID, Response: []byte(summary),
	})

	logOperationEvent(taskData.Task.ID,
		fmt.Sprintf("[TOKEN] Auto-verify complete: %d privileges", privCount), false)
	return response
}
