package agentfunctions

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
	"github.com/MythicMeta/MythicContainer/mythicrpc"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name: "security-info",
		AssociatedBrowserScript: &agentstructs.BrowserScript{
			ScriptPath: filepath.Join(".", "fawkes", "browserscripts", "securityinfo_new.js"),
			Author:     "@GlobeTech",
		},
		Description:         "Report security posture and active controls, or detect installed EDR/XDR products. Linux: SELinux, AppArmor, seccomp, ASLR, YAMA, LSM, BPF. macOS: SIP, Gatekeeper, FileVault, MDM, TCC, SSH, JAMF, ARD. Windows: Defender, Credential Guard, UAC, BitLocker, CLM.",
		HelpString:          "security-info [-action all|edr]",
		Version:             4,
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1082", "T1518.001"},
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{
				agentstructs.SUPPORTED_OS_WINDOWS,
				agentstructs.SUPPORTED_OS_LINUX,
				agentstructs.SUPPORTED_OS_MACOS,
			},
		},
		TaskCompletionFunctions: map[string]agentstructs.PTTaskCompletionFunction{
			"stealthPrepSecInfoDone": stealthPrepSecInfoDone,
			"stealthPrepAutopatchDone": stealthPrepAutopatchDone,
			"stealthPrepEtwDone": stealthPrepEtwDone,
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:             "action",
				ModalDisplayName: "Action",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Description:      "all: report security posture (default). edr: detect installed EDR/XDR/AV products. stealth-prep: automated stealth chain (security-info → autopatch → etw blind).",
				Choices:          []string{"all", "edr", "stealth-prep"},
				DefaultValue:     "all",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
						UIModalPosition:     0,
					},
				},
			},
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
		TaskFunctionOPSECPre: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTTaskOPSECPreTaskMessageResponse {
			return agentstructs.PTTTaskOPSECPreTaskMessageResponse{
				TaskID:             taskData.Task.ID,
				Success:            true,
				OpsecPreBlocked:    false,
				OpsecPreMessage:    "OPSEC WARNING: Security configuration extraction enumerates firewall rules, AV status, EDR products, and security policies. This is a common reconnaissance pattern that security monitoring tools specifically watch for.",
				OpsecPreBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionOPSECPost: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskOPSECPostTaskMessageResponse {
			return agentstructs.PTTaskOPSECPostTaskMessageResponse{
				TaskID:              taskData.Task.ID,
				Success:             true,
				OpsecPostBlocked:    false,
				OpsecPostMessage:    "OPSEC AUDIT: Security configuration enumerated. Querying EDR, firewall, and AV status reveals defensive posture. WMI/registry queries for security products may be logged.",
				OpsecPostBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionCreateTasking: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{Success: true, TaskID: taskData.Task.ID}
			action, _ := taskData.Args.GetStringArg("action")
			if action == "" {
				action = "all"
			}

			if action == "stealth-prep" {
				display := "Stealth Prep Chain (security-info → autopatch → etw blind)"
				response.DisplayParams = &display

				// Step 1: Run security-info to assess environment
				callbackFunc := "stealthPrepSecInfoDone"
				secInfoParams, _ := json.Marshal(map[string]string{"action": "all"})
				_, err := mythicrpc.SendMythicRPCTaskCreateSubtask(
					mythicrpc.MythicRPCTaskCreateSubtaskMessage{
						TaskID:                  taskData.Task.ID,
						SubtaskCallbackFunction: &callbackFunc,
						CommandName:             "security-info",
						Params:                  string(secInfoParams),
					},
				)
				if err != nil {
					response.Success = false
					errMsg := fmt.Sprintf("Failed to create security-info subtask: %v", err)
					response.Error = errMsg
					return response
				}

				createArtifact(taskData.Task.ID, "Subtask Chain",
					"Stealth Prep: security-info → autopatch → etw blind (sequential)")
				return response
			}

			display := fmt.Sprintf("action: %s", action)
			response.DisplayParams = &display

			params := map[string]string{"action": action}
			paramsJSON, _ := json.Marshal(params)
			taskData.Args.SetManualArgs(string(paramsJSON))

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
			if action == "edr" {
				// Parse EDR detection JSON output and register detected products as artifacts
				// Output format: text header followed by JSON array of edrDetection objects
				jsonStart := strings.Index(responseText, "[")
				if jsonStart < 0 {
					return response
				}
				var detections []struct {
					Name    string `json:"name"`
					Vendor  string `json:"vendor"`
					Status  string `json:"status"`
					Process string `json:"process,omitempty"`
					PID     int    `json:"pid,omitempty"`
				}
				if err := json.Unmarshal([]byte(responseText[jsonStart:]), &detections); err != nil {
					return response
				}
				var activeProducts []string
				for _, d := range detections {
					if d.Status == "running" || d.Status == "installed" {
						detail := fmt.Sprintf("[EDR] %s (%s) — %s", d.Name, d.Vendor, d.Status)
						if d.Process != "" {
							detail += fmt.Sprintf(" (process: %s", d.Process)
							if d.PID > 0 {
								detail += fmt.Sprintf(", PID %d", d.PID)
							}
							detail += ")"
						}
						createArtifact(processResponse.TaskData.Task.ID, "Host Discovery", detail)
						activeProducts = append(activeProducts, d.Name)
					}
				}
				if len(activeProducts) > 0 {
					tagTask(processResponse.TaskData.Task.ID, "EDR",
						fmt.Sprintf("Detected %d active security products: %s", len(activeProducts), strings.Join(activeProducts, ", ")))
				}
				// Cache EDR detection results in AgentStorage for cross-callback reference
				callbackID := fmt.Sprintf("%d", processResponse.TaskData.Callback.DisplayID)
				storageKey := "edr-detections-cb" + callbackID
				if storageData, err := json.Marshal(detections); err == nil {
					storeAgentData(storageKey, storageData)
				}
			}
			return response
		},
	})
}

// stealthPrepSecInfoDone handles security-info completion → triggers autopatch
func stealthPrepSecInfoDone(
	taskData *agentstructs.PTTaskMessageAllData,
	subtaskData *agentstructs.PTTaskMessageAllData,
	groupName *agentstructs.SubtaskGroupName,
) agentstructs.PTTaskCompletionFunctionMessageResponse {
	response := agentstructs.PTTaskCompletionFunctionMessageResponse{
		TaskID:  taskData.Task.ID,
		Success: true,
	}

	mythicrpc.SendMythicRPCResponseCreate(mythicrpc.MythicRPCResponseCreateMessage{
		TaskID:   taskData.Task.ID,
		Response: []byte("[1/3] Security-info complete. Proceeding to autopatch..."),
	})

	// Step 2: Run autopatch to patch AMSI/ETW hooks
	callbackFunc := "stealthPrepAutopatchDone"
	autopatchParams, _ := json.Marshal(map[string]string{})
	_, err := mythicrpc.SendMythicRPCTaskCreateSubtask(
		mythicrpc.MythicRPCTaskCreateSubtaskMessage{
			TaskID:                  taskData.Task.ID,
			SubtaskCallbackFunction: &callbackFunc,
			CommandName:             "autopatch",
			Params:                  string(autopatchParams),
		},
	)
	if err != nil {
		response.Success = false
		errMsg := fmt.Sprintf("Failed to create autopatch subtask: %v", err)
		response.Error = errMsg
	}

	return response
}

// stealthPrepAutopatchDone handles autopatch completion → triggers etw blind
func stealthPrepAutopatchDone(
	taskData *agentstructs.PTTaskMessageAllData,
	subtaskData *agentstructs.PTTaskMessageAllData,
	groupName *agentstructs.SubtaskGroupName,
) agentstructs.PTTaskCompletionFunctionMessageResponse {
	response := agentstructs.PTTaskCompletionFunctionMessageResponse{
		TaskID:  taskData.Task.ID,
		Success: true,
	}

	mythicrpc.SendMythicRPCResponseCreate(mythicrpc.MythicRPCResponseCreateMessage{
		TaskID:   taskData.Task.ID,
		Response: []byte("[2/3] Autopatch complete. Proceeding to ETW blind..."),
	})

	// Step 3: Run etw blind to disable ETW logging
	callbackFunc := "stealthPrepEtwDone"
	etwParams, _ := json.Marshal(map[string]string{"action": "blind"})
	_, err := mythicrpc.SendMythicRPCTaskCreateSubtask(
		mythicrpc.MythicRPCTaskCreateSubtaskMessage{
			TaskID:                  taskData.Task.ID,
			SubtaskCallbackFunction: &callbackFunc,
			CommandName:             "etw",
			Params:                  string(etwParams),
		},
	)
	if err != nil {
		response.Success = false
		errMsg := fmt.Sprintf("Failed to create etw subtask: %v", err)
		response.Error = errMsg
	}

	return response
}

// stealthPrepEtwDone handles etw blind completion → aggregates final results
func stealthPrepEtwDone(
	taskData *agentstructs.PTTaskMessageAllData,
	subtaskData *agentstructs.PTTaskMessageAllData,
	groupName *agentstructs.SubtaskGroupName,
) agentstructs.PTTaskCompletionFunctionMessageResponse {
	response := agentstructs.PTTaskCompletionFunctionMessageResponse{
		TaskID:  taskData.Task.ID,
		Success: true,
	}

	parentID := taskData.Task.ID
	searchResult, err := mythicrpc.SendMythicRPCTaskSearch(mythicrpc.MythicRPCTaskSearchMessage{
		TaskID:             parentID,
		SearchParentTaskID: &parentID,
	})

	var summaryParts []string
	successCount := 0
	errorCount := 0

	if err == nil && searchResult.Success {
		for _, task := range searchResult.Tasks {
			status := "UNKNOWN"
			if task.Completed {
				if task.Status == "error" {
					status = "ERROR"
					errorCount++
				} else {
					status = "SUCCESS"
					successCount++
				}
			}
			summaryParts = append(summaryParts, fmt.Sprintf("[%s] %s: %s", status, task.CommandName, task.DisplayParams))
		}
	}

	completed := true
	response.Completed = &completed

	summary := fmt.Sprintf("=== Stealth Environment Preparation Complete ===\nSteps: %d success, %d errors\n\n%s\n\nEnvironment should now have:\n  - AMSI hooks patched (autopatch)\n  - ETW event logging blinded (etw blind)\n  - Security posture documented (security-info)",
		successCount, errorCount, strings.Join(summaryParts, "\n"))
	response.Stdout = &summary

	mythicrpc.SendMythicRPCResponseCreate(mythicrpc.MythicRPCResponseCreateMessage{
		TaskID:   parentID,
		Response: []byte(summary),
	})

	logOperationEvent(parentID,
		fmt.Sprintf("[STEALTH] Stealth prep chain complete on %s (%d/%d steps succeeded)", taskData.Callback.Host, successCount, successCount+errorCount), true)

	return response
}
