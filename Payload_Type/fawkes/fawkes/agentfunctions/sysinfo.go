package agentfunctions

import (
	"fmt"
	"strconv"
	"strings"

	"path/filepath"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
	"github.com/MythicMeta/MythicContainer/logging"
	"github.com/MythicMeta/MythicContainer/mythicrpc"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "sysinfo",
		Description:         "sysinfo - Collect comprehensive system information: OS version, hardware, memory, uptime, domain membership, .NET versions (Windows), SELinux/SIP status, virtualization detection. Use 'full-profile' action for automated host profiling chain.",
		HelpString:          "sysinfo\nsysinfo -action full-profile",
		Version:             2,
		MitreAttackMappings: []string{"T1082"}, // System Information Discovery
		Author:              "@galoryber",
		AssociatedBrowserScript: &agentstructs.BrowserScript{ScriptPath: filepath.Join(".", "fawkes", "browserscripts", "sysinfo_new.js"), Author: "@galoryber"},
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_LINUX, agentstructs.SUPPORTED_OS_MACOS, agentstructs.SUPPORTED_OS_WINDOWS},
		},
		TaskCompletionFunctions: map[string]agentstructs.PTTaskCompletionFunction{
			"hostProfileSysinfoDone":    hostProfileSysinfoDone,
			"hostProfilePsDone":         hostProfilePsDone,
			"hostProfileSecurityDone":   hostProfileSecurityDone,
			"hostProfilePrivescDone":    hostProfilePrivescDone,
			"hostProfilePersistDone":    hostProfilePersistDone,
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:             "action",
				CLIName:          "action",
				ModalDisplayName: "Action",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:          []string{"info", "full-profile"},
				Description:      "info: collect system information (default). full-profile: automated 5-step host profiling chain (sysinfo → ps → security-info → privesc-check → persist-enum).",
				DefaultValue:     "info",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
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
			update := mythicrpc.MythicRPCCallbackUpdateMessage{
				AgentCallbackID: &processResponse.TaskData.Callback.AgentCallbackID,
			}
			hasUpdate := false
			for _, line := range strings.Split(responseText, "\n") {
				trimmed := strings.TrimSpace(line)
				if val := extractField(trimmed, "Hostname:"); val != "" {
					update.Host = &val
					hasUpdate = true
				} else if val := extractField(trimmed, "OS:"); val != "" {
					update.Os = &val
					hasUpdate = true
				} else if val := extractField(trimmed, "Architecture:"); val != "" {
					update.Architecture = &val
					hasUpdate = true
				} else if val := extractField(trimmed, "PID:"); val != "" {
					if pid, err := strconv.Atoi(val); err == nil {
						update.PID = &pid
						hasUpdate = true
					}
				} else if val := extractField(trimmed, "Domain:"); val != "" {
					if !strings.Contains(val, "not domain-joined") {
						update.Domain = &val
						hasUpdate = true
					}
				} else if val := extractField(trimmed, "FQDN:"); val != "" {
					update.Host = &val
					hasUpdate = true
				} else if val := extractField(trimmed, "Elevated:"); val != "" {
					if strings.EqualFold(val, "true") {
						level := 3 // High
						update.IntegrityLevel = &level
						hasUpdate = true
					}
				}
			}
			if hasUpdate {
				if _, err := mythicrpc.SendMythicRPCCallbackUpdate(update); err != nil {
					logging.LogError(err, "Failed to update callback metadata from sysinfo")
				}
			}
			return response
		},
		TaskFunctionOPSECPre: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTTaskOPSECPreTaskMessageResponse {
			return agentstructs.PTTTaskOPSECPreTaskMessageResponse{
				TaskID:             taskData.Task.ID,
				Success:            true,
				OpsecPreBlocked:    false,
				OpsecPreMessage:    "OPSEC WARNING: System information discovery collects OS version, hardware details, hostname, domain, and network configuration. Standard reconnaissance footprint — commonly baselined by EDR.",
				OpsecPreBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionOPSECPost: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskOPSECPostTaskMessageResponse {
			return agentstructs.PTTaskOPSECPostTaskMessageResponse{
				TaskID:              taskData.Task.ID,
				Success:             true,
				OpsecPostBlocked:    false,
				OpsecPostMessage:    "OPSEC AUDIT: System information collected. Comprehensive system enumeration reveals OS version, hardware, domain membership. WMI queries may be logged by EDR.",
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
			if action == "full-profile" {
				display := "Full Host Profile: sysinfo → ps → security-info → privesc-check → persist-enum"
				response.DisplayParams = &display

				callbackFunc := "hostProfileSysinfoDone"
				_, err := mythicrpc.SendMythicRPCTaskCreateSubtask(
					mythicrpc.MythicRPCTaskCreateSubtaskMessage{
						TaskID:                  taskData.Task.ID,
						SubtaskCallbackFunction: &callbackFunc,
						CommandName:             "sysinfo",
						Params:                  `{"action":"info"}`,
					},
				)
				if err != nil {
					response.Success = false
					errMsg := fmt.Sprintf("Failed to start host profile chain: %v", err)
					response.Error = errMsg
					return response
				}
				createArtifact(taskData.Task.ID, "Subtask Chain",
					"Host Profile chain: sysinfo → ps → security-info → privesc-check → persist-enum")
				return response
			}
			return response
		},
	})
}

// --- Host Profile Subtask Chain Completion Functions ---

// Step 1: sysinfo done → trigger ps
func hostProfileSysinfoDone(
	taskData *agentstructs.PTTaskMessageAllData,
	subtaskData *agentstructs.PTTaskMessageAllData,
	_ *agentstructs.SubtaskGroupName,
) agentstructs.PTTaskCompletionFunctionMessageResponse {
	response := agentstructs.PTTaskCompletionFunctionMessageResponse{
		TaskID:  taskData.Task.ID,
		Success: true,
	}

	mythicrpc.SendMythicRPCResponseCreate(mythicrpc.MythicRPCResponseCreateMessage{
		TaskID:   taskData.Task.ID,
		Response: []byte("[1/5] System info collected. Running process enumeration..."),
	})

	callbackFunc := "hostProfilePsDone"
	_, err := mythicrpc.SendMythicRPCTaskCreateSubtask(
		mythicrpc.MythicRPCTaskCreateSubtaskMessage{
			TaskID:                  taskData.Task.ID,
			SubtaskCallbackFunction: &callbackFunc,
			CommandName:             "ps",
			Params:                  `{}`,
		},
	)
	if err != nil {
		response.Success = false
		response.Error = fmt.Sprintf("Failed to create ps subtask: %v", err)
	}
	return response
}

// Step 2: ps done → trigger security-info
func hostProfilePsDone(
	taskData *agentstructs.PTTaskMessageAllData,
	subtaskData *agentstructs.PTTaskMessageAllData,
	_ *agentstructs.SubtaskGroupName,
) agentstructs.PTTaskCompletionFunctionMessageResponse {
	response := agentstructs.PTTaskCompletionFunctionMessageResponse{
		TaskID:  taskData.Task.ID,
		Success: true,
	}

	mythicrpc.SendMythicRPCResponseCreate(mythicrpc.MythicRPCResponseCreateMessage{
		TaskID:   taskData.Task.ID,
		Response: []byte("[2/5] Process enumeration complete. Checking security posture..."),
	})

	callbackFunc := "hostProfileSecurityDone"
	_, err := mythicrpc.SendMythicRPCTaskCreateSubtask(
		mythicrpc.MythicRPCTaskCreateSubtaskMessage{
			TaskID:                  taskData.Task.ID,
			SubtaskCallbackFunction: &callbackFunc,
			CommandName:             "security-info",
			Params:                  `{"action":"all"}`,
		},
	)
	if err != nil {
		response.Success = false
		response.Error = fmt.Sprintf("Failed to create security-info subtask: %v", err)
	}
	return response
}

// Step 3: security-info done → trigger privesc-check
func hostProfileSecurityDone(
	taskData *agentstructs.PTTaskMessageAllData,
	subtaskData *agentstructs.PTTaskMessageAllData,
	_ *agentstructs.SubtaskGroupName,
) agentstructs.PTTaskCompletionFunctionMessageResponse {
	response := agentstructs.PTTaskCompletionFunctionMessageResponse{
		TaskID:  taskData.Task.ID,
		Success: true,
	}

	mythicrpc.SendMythicRPCResponseCreate(mythicrpc.MythicRPCResponseCreateMessage{
		TaskID:   taskData.Task.ID,
		Response: []byte("[3/5] Security posture assessed. Checking privilege escalation vectors..."),
	})

	callbackFunc := "hostProfilePrivescDone"
	_, err := mythicrpc.SendMythicRPCTaskCreateSubtask(
		mythicrpc.MythicRPCTaskCreateSubtaskMessage{
			TaskID:                  taskData.Task.ID,
			SubtaskCallbackFunction: &callbackFunc,
			CommandName:             "privesc-check",
			Params:                  `{"action":"all"}`,
		},
	)
	if err != nil {
		response.Success = false
		response.Error = fmt.Sprintf("Failed to create privesc-check subtask: %v", err)
	}
	return response
}

// Step 4: privesc-check done → trigger persist-enum
func hostProfilePrivescDone(
	taskData *agentstructs.PTTaskMessageAllData,
	subtaskData *agentstructs.PTTaskMessageAllData,
	_ *agentstructs.SubtaskGroupName,
) agentstructs.PTTaskCompletionFunctionMessageResponse {
	response := agentstructs.PTTaskCompletionFunctionMessageResponse{
		TaskID:  taskData.Task.ID,
		Success: true,
	}

	mythicrpc.SendMythicRPCResponseCreate(mythicrpc.MythicRPCResponseCreateMessage{
		TaskID:   taskData.Task.ID,
		Response: []byte("[4/5] Privilege escalation check complete. Enumerating persistence mechanisms..."),
	})

	callbackFunc := "hostProfilePersistDone"
	_, err := mythicrpc.SendMythicRPCTaskCreateSubtask(
		mythicrpc.MythicRPCTaskCreateSubtaskMessage{
			TaskID:                  taskData.Task.ID,
			SubtaskCallbackFunction: &callbackFunc,
			CommandName:             "persist-enum",
			Params:                  `{"category":"all"}`,
		},
	)
	if err != nil {
		response.Success = false
		response.Error = fmt.Sprintf("Failed to create persist-enum subtask: %v", err)
	}
	return response
}

// Step 5 (Final): persist-enum done → aggregate results and complete chain
func hostProfilePersistDone(
	taskData *agentstructs.PTTaskMessageAllData,
	subtaskData *agentstructs.PTTaskMessageAllData,
	_ *agentstructs.SubtaskGroupName,
) agentstructs.PTTaskCompletionFunctionMessageResponse {
	response := agentstructs.PTTaskCompletionFunctionMessageResponse{
		TaskID:  taskData.Task.ID,
		Success: true,
	}

	// Search for all subtasks to build summary
	parentID := taskData.Task.ID
	searchResult, err := mythicrpc.SendMythicRPCTaskSearch(mythicrpc.MythicRPCTaskSearchMessage{
		TaskID:             parentID,
		SearchParentTaskID: &parentID,
	})

	summary := "=== Host Profile Complete ===\n"
	successCount := 0
	errorCount := 0
	if err == nil && searchResult.Success {
		for _, task := range searchResult.Tasks {
			status := "✓"
			if task.Status == "error" {
				status = "✗"
				errorCount++
			} else {
				successCount++
			}
			summary += fmt.Sprintf("  %s %s\n", status, task.CommandName)
		}
	}
	summary += fmt.Sprintf("\nSteps: %d/%d successful\n", successCount, successCount+errorCount)
	summary += "View individual subtask results for detailed findings."

	completed := true
	response.Completed = &completed
	response.Stdout = &summary

	mythicrpc.SendMythicRPCResponseCreate(mythicrpc.MythicRPCResponseCreateMessage{
		TaskID:   taskData.Task.ID,
		Response: []byte(summary),
	})

	logOperationEvent(taskData.Task.ID,
		fmt.Sprintf("[RECON] Host profile completed on %s: %d/%d steps successful",
			taskData.Callback.Host, successCount, successCount+errorCount), false)

	return response
}

// extractField extracts the value after a "Key:" prefix from a trimmed line.
func extractField(line, prefix string) string {
	if strings.HasPrefix(line, prefix) {
		return strings.TrimSpace(strings.TrimPrefix(line, prefix))
	}
	return ""
}
