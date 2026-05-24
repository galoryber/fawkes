package agentfunctions

import (
	"fmt"
	"path/filepath"
	"strings"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
	"github.com/MythicMeta/MythicContainer/logging"
	"github.com/MythicMeta/MythicContainer/mythicrpc"
)

// Chain completion functions for getsystem auto
func getsystemAutoEnumDone(taskData *agentstructs.PTTaskMessageAllData, subtaskData *agentstructs.PTTaskMessageAllData, _ *agentstructs.SubtaskGroupName) agentstructs.PTTaskCompletionFunctionMessageResponse {
	response := agentstructs.PTTaskCompletionFunctionMessageResponse{TaskID: taskData.Task.ID, Success: true}
	mythicrpc.SendMythicRPCResponseCreate(mythicrpc.MythicRPCResponseCreateMessage{
		TaskID: taskData.Task.ID, Response: []byte("[1/4] Token enumeration complete. Stealing SYSTEM token..."),
	})
	cb := "getsystemAutoStealDone"
	if _, err := mythicrpc.SendMythicRPCTaskCreateSubtask(mythicrpc.MythicRPCTaskCreateSubtaskMessage{
		TaskID: taskData.Task.ID, SubtaskCallbackFunction: &cb, CommandName: "getsystem", Params: `{"technique":"steal"}`,
	}); err != nil {
		response.Success = false
		response.Error = fmt.Sprintf("Failed to create steal-token subtask: %v", err)
	}
	return response
}

func getsystemAutoStealDone(taskData *agentstructs.PTTaskMessageAllData, subtaskData *agentstructs.PTTaskMessageAllData, _ *agentstructs.SubtaskGroupName) agentstructs.PTTaskCompletionFunctionMessageResponse {
	response := agentstructs.PTTaskCompletionFunctionMessageResponse{TaskID: taskData.Task.ID, Success: true}
	if subtaskData.Task.Status == "error" {
		mythicrpc.SendMythicRPCResponseCreate(mythicrpc.MythicRPCResponseCreateMessage{
			TaskID: taskData.Task.ID, Response: []byte("[2/4] Token steal failed. Attempting potato technique..."),
		})
		cb := "getsystemAutoPotatoDone"
		if _, err := mythicrpc.SendMythicRPCTaskCreateSubtask(mythicrpc.MythicRPCTaskCreateSubtaskMessage{
			TaskID: taskData.Task.ID, SubtaskCallbackFunction: &cb, CommandName: "getsystem", Params: `{"technique":"potato"}`,
		}); err != nil {
			response.Success = false
			response.Error = fmt.Sprintf("Failed to create potato subtask: %v", err)
		}
		return response
	}
	mythicrpc.SendMythicRPCResponseCreate(mythicrpc.MythicRPCResponseCreateMessage{
		TaskID: taskData.Task.ID, Response: []byte("[2/4] SYSTEM token stolen. Verifying identity..."),
	})
	cb := "getsystemAutoWhoamiDone"
	if _, err := mythicrpc.SendMythicRPCTaskCreateSubtask(mythicrpc.MythicRPCTaskCreateSubtaskMessage{
		TaskID: taskData.Task.ID, SubtaskCallbackFunction: &cb, CommandName: "whoami", Params: `{}`,
	}); err != nil {
		response.Success = false
		response.Error = fmt.Sprintf("Failed to create whoami subtask: %v", err)
	}
	return response
}

func getsystemAutoPotatoDone(taskData *agentstructs.PTTaskMessageAllData, subtaskData *agentstructs.PTTaskMessageAllData, _ *agentstructs.SubtaskGroupName) agentstructs.PTTaskCompletionFunctionMessageResponse {
	response := agentstructs.PTTaskCompletionFunctionMessageResponse{TaskID: taskData.Task.ID, Success: true}
	if subtaskData.Task.Status == "error" {
		completed := true
		response.Completed = &completed
		summary := "=== Auto Privesc Failed ===\nBoth steal and potato techniques failed. Manual escalation required."
		response.Stdout = &summary
		mythicrpc.SendMythicRPCResponseCreate(mythicrpc.MythicRPCResponseCreateMessage{
			TaskID: taskData.Task.ID, Response: []byte(summary),
		})
		return response
	}
	mythicrpc.SendMythicRPCResponseCreate(mythicrpc.MythicRPCResponseCreateMessage{
		TaskID: taskData.Task.ID, Response: []byte("[2/4] Potato escalation succeeded. Verifying identity..."),
	})
	cb := "getsystemAutoWhoamiDone"
	if _, err := mythicrpc.SendMythicRPCTaskCreateSubtask(mythicrpc.MythicRPCTaskCreateSubtaskMessage{
		TaskID: taskData.Task.ID, SubtaskCallbackFunction: &cb, CommandName: "whoami", Params: `{}`,
	}); err != nil {
		response.Success = false
		response.Error = fmt.Sprintf("Failed to create whoami subtask: %v", err)
	}
	return response
}

func getsystemAutoWhoamiDone(taskData *agentstructs.PTTaskMessageAllData, subtaskData *agentstructs.PTTaskMessageAllData, _ *agentstructs.SubtaskGroupName) agentstructs.PTTaskCompletionFunctionMessageResponse {
	response := agentstructs.PTTaskCompletionFunctionMessageResponse{TaskID: taskData.Task.ID, Success: true}
	mythicrpc.SendMythicRPCResponseCreate(mythicrpc.MythicRPCResponseCreateMessage{
		TaskID: taskData.Task.ID, Response: []byte("[3/4] Identity verified. Enumerating privileges..."),
	})
	cb := "getsystemAutoGetprivsDone"
	if _, err := mythicrpc.SendMythicRPCTaskCreateSubtask(mythicrpc.MythicRPCTaskCreateSubtaskMessage{
		TaskID: taskData.Task.ID, SubtaskCallbackFunction: &cb, CommandName: "getprivs", Params: `{}`,
	}); err != nil {
		response.Success = false
		response.Error = fmt.Sprintf("Failed to create getprivs subtask: %v", err)
	}
	return response
}

func getsystemAutoGetprivsDone(taskData *agentstructs.PTTaskMessageAllData, subtaskData *agentstructs.PTTaskMessageAllData, _ *agentstructs.SubtaskGroupName) agentstructs.PTTaskCompletionFunctionMessageResponse {
	response := agentstructs.PTTaskCompletionFunctionMessageResponse{TaskID: taskData.Task.ID, Success: true}
	parentID := taskData.Task.ID
	searchResult, _ := mythicrpc.SendMythicRPCTaskSearch(mythicrpc.MythicRPCTaskSearchMessage{
		TaskID: parentID, SearchParentTaskID: &parentID,
	})
	summary := "=== Auto Privilege Escalation Complete ===\n"
	successCount := 0
	errorCount := 0
	if searchResult != nil && searchResult.Success {
		for _, task := range searchResult.Tasks {
			status := "OK"
			if task.Status == "error" {
				status = "FAIL"
				errorCount++
			} else {
				successCount++
			}
			summary += fmt.Sprintf("  [%s] %s\n", status, task.CommandName)
		}
	}
	summary += fmt.Sprintf("\nSteps: %d/%d successful\n", successCount, successCount+errorCount)
	completed := true
	response.Completed = &completed
	response.Stdout = &summary
	mythicrpc.SendMythicRPCResponseCreate(mythicrpc.MythicRPCResponseCreateMessage{
		TaskID: taskData.Task.ID, Response: []byte(summary),
	})
	logOperationEvent(taskData.Task.ID, fmt.Sprintf("[PRIVESC] Auto escalation on %s: %d/%d steps successful", taskData.Callback.Host, successCount, successCount+errorCount), false)
	return response
}

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "getsystem",
		Description:         "Privilege escalation. Windows: SYSTEM via token steal or DCOM potato. Linux: root via sudo, SUID, capabilities check. macOS: root via sudo or osascript elevation prompt.",
		HelpString:          "# Windows\ngetsystem -technique steal\ngetsystem -technique potato\n# Linux\ngetsystem -technique check\ngetsystem -technique sudo\n# macOS\ngetsystem -technique check\ngetsystem -technique sudo\ngetsystem -technique osascript",
		Version:             4,
		SupportedUIFeatures: []string{},
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1134.001", "T1548.001", "T1548.003", "T1059.002"},
		ScriptOnlyCommand: false,
		TaskCompletionFunctions: map[string]agentstructs.PTTaskCompletionFunction{
			"getsystemAutoEnumDone":     getsystemAutoEnumDone,
			"getsystemAutoStealDone":    getsystemAutoStealDone,
			"getsystemAutoPotatoDone":   getsystemAutoPotatoDone,
			"getsystemAutoWhoamiDone":   getsystemAutoWhoamiDone,
			"getsystemAutoGetprivsDone": getsystemAutoGetprivsDone,
		},
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{
				agentstructs.SUPPORTED_OS_WINDOWS,
				agentstructs.SUPPORTED_OS_LINUX,
				agentstructs.SUPPORTED_OS_MACOS,
			},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:             "technique",
				ModalDisplayName: "Technique",
				CLIName:          "technique",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:          []string{"steal", "potato", "check", "sudo", "osascript", "auto"},
				Description:      "Windows: steal (token theft, needs admin) or potato (DCOM OXID, needs service). Linux: check (enumerate vectors) or sudo (attempt elevation). macOS: check, sudo, or osascript (admin prompt).",
				DefaultValue:     "check",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
		},
		AssociatedBrowserScript: &agentstructs.BrowserScript{ScriptPath: filepath.Join(".", "fawkes", "browserscripts", "getsystem_new.js"), Author: "@galoryber"},
		TaskFunctionOPSECPre: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTTaskOPSECPreTaskMessageResponse {
			technique, _ := taskData.Args.GetStringArg("technique")
			var msg string
			switch technique {
			case "steal":
				msg = "OPSEC WARNING: Token theft from SYSTEM process via OpenProcessToken + DuplicateTokenEx. Requires SeDebugPrivilege. Token manipulation is a high-fidelity EDR detection."
			case "potato":
				msg = "OPSEC WARNING: DCOM potato privilege escalation via OXID resolution hook + named pipe impersonation. Creates artifacts in RPC dispatch table."
			case "sudo":
				msg = "OPSEC WARNING: Privilege escalation via sudo. Command execution visible in process tree and auth.log/secure. Failed attempts logged."
			case "osascript":
				msg = "OPSEC WARNING: Privilege escalation via AppleScript admin prompt. Triggers a visible UI dialog. User may deny or report. Auth attempt logged in unified logging."
			case "auto":
				msg = "OPSEC WARNING: Auto privilege escalation chain — enumerates tokens, attempts steal then potato, verifies with whoami + getprivs. Multiple high-risk operations in sequence. Token manipulation and DCOM operations trigger EDR detections."
			case "check":
				msg = "OPSEC NOTE: Enumerating privilege escalation vectors. Low risk — reads filesystem and checks permissions. sudo -l may generate an auth log entry."
			default:
				msg = "OPSEC WARNING: Privilege escalation attempt. May trigger alerts."
			}
			return agentstructs.PTTTaskOPSECPreTaskMessageResponse{
				TaskID: taskData.Task.ID, Success: true,
				OpsecPreBlocked: false, OpsecPreMessage: msg,
				OpsecPreBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionOPSECPost: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskOPSECPostTaskMessageResponse {
			return agentstructs.PTTaskOPSECPostTaskMessageResponse{
				TaskID:              taskData.Task.ID,
				Success:             true,
				OpsecPostBlocked:    false,
				OpsecPostMessage:    "OPSEC AUDIT: Privilege escalation completed. Token theft from winlogon/lsass and DCOM operations generate process access events (Event ID 4688, 4656). Callback metadata updated to SYSTEM. Integrity level change is visible in Mythic UI.",
				OpsecPostBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionParseArgString: func(args *agentstructs.PTTaskMessageArgsData, input string) error {
			if input == "" {
				return nil
			}
			if err := args.LoadArgsFromJSONString(input); err != nil {
				// Plain text fallback: treat input as technique name
				input = strings.TrimSpace(input)
				return args.SetArgValue("technique", input)
			}
			return nil
		},
		TaskFunctionParseArgDictionary: func(args *agentstructs.PTTaskMessageArgsData, input map[string]interface{}) error {
			return args.LoadArgsFromDictionary(input)
		},
		TaskFunctionCreateTasking: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  taskData.Task.ID,
			}
			technique, _ := taskData.Args.GetStringArg("technique")
			if technique == "" {
				technique = "steal"
			}
			if technique == "auto" {
				display := "technique: auto (chain: enum-tokens → steal/potato → whoami → getprivs)"
				response.DisplayParams = &display
				// Change agent-side technique to "check" for safe execution
				taskData.Args.SetArgValue("technique", "check")
				// Start chain: enum-tokens first
				cb := "getsystemAutoEnumDone"
				if _, err := mythicrpc.SendMythicRPCTaskCreateSubtask(mythicrpc.MythicRPCTaskCreateSubtaskMessage{
					TaskID: taskData.Task.ID, SubtaskCallbackFunction: &cb, CommandName: "enum-tokens", Params: `{}`,
				}); err != nil {
					response.Success = false
					response.Error = fmt.Sprintf("Failed to start auto chain: %v", err)
					return response
				}
				createArtifact(taskData.Task.ID, "Subtask Chain", "Auto Privesc: enum-tokens → steal/potato → whoami → getprivs")
				return response
			}
			display := fmt.Sprintf("technique: %s", technique)
			response.DisplayParams = &display
			switch technique {
			case "potato":
				createArtifact(taskData.Task.ID, "DCOM OXID Hook", "combase.dll RPC dispatch table hook + named pipe impersonation")
			default:
				createArtifact(taskData.Task.ID, "Token Steal", "OpenProcess + OpenProcessToken + DuplicateTokenEx on SYSTEM process")
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
			// On successful SYSTEM escalation, update callback IntegrityLevel
			if !strings.Contains(responseText, "Successfully elevated to SYSTEM") {
				return response
			}
			systemLevel := 4 // SYSTEM integrity
			update := mythicrpc.MythicRPCCallbackUpdateMessage{
				AgentCallbackID: &processResponse.TaskData.Callback.AgentCallbackID,
				IntegrityLevel:    &systemLevel,
			}
			// Parse user from "New:" line
			user := ""
			for _, line := range strings.Split(responseText, "\n") {
				trimmed := strings.TrimSpace(line)
				if val := extractField(trimmed, "New:"); val != "" {
					user = val
					update.User = &val
					break
				}
			}
			if _, err := mythicrpc.SendMythicRPCCallbackUpdate(update); err != nil {
				logging.LogError(err, "Failed to update callback metadata after getsystem")
			}
			tagTask(processResponse.TaskData.Task.ID, "SYSTEM",
				fmt.Sprintf("SYSTEM-level access obtained on %s", processResponse.TaskData.Callback.Host))
			// Register SYSTEM token with Mythic's token tracker
			if user == "" {
				user = "NT AUTHORITY\\SYSTEM"
			}
			host := processResponse.TaskData.Callback.Host
			if _, err := mythicrpc.SendMythicRPCCallbackTokenCreate(mythicrpc.MythicRPCCallbackTokenCreateMessage{
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
			}); err != nil {
				logging.LogError(err, "Failed to register SYSTEM token with Mythic")
			}
			return response
		},
	})
}
