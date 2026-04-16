package agentfunctions

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
	"github.com/MythicMeta/MythicContainer/logging"
	"github.com/MythicMeta/MythicContainer/mythicrpc"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "ldap-query",
		Description:         "Query Active Directory via LDAP. Supports preset queries (users, computers, groups, domain-admins, admins, SPNs, AS-REP roastable, disabled, GPOs, OUs, password-never-expires, trusts, unconstrained/constrained delegation) and custom LDAP filters.",
		HelpString:          "ldap-query -action users -server 192.168.1.1\nldap-query -action trusts -server dc01\nldap-query -action unconstrained -server dc01\nldap-query -action constrained -server dc01\nldap-query -action query -server dc01 -filter \"(servicePrincipalName=*MSSQLSvc*)\"",
		Version:             3,
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1087.002", "T1069.002"},
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{
				agentstructs.SUPPORTED_OS_WINDOWS,
				agentstructs.SUPPORTED_OS_LINUX,
				agentstructs.SUPPORTED_OS_MACOS,
			},
		},
		AssociatedBrowserScript: &agentstructs.BrowserScript{ScriptPath: filepath.Join(".", "fawkes", "browserscripts", "ldap_query_new.js"), Author: "@galoryber"},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:             "action",
				CLIName:          "action",
				ModalDisplayName: "Query Type",
				Description:      "Preset query or custom filter",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:          []string{"users", "computers", "groups", "domain-admins", "spns", "asrep", "admins", "disabled", "gpo", "ou", "password-never-expires", "trusts", "unconstrained", "constrained", "dacl", "gmsa", "query", "enum-chain"},
				DefaultValue:     "users",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: true, GroupName: "Default"},
				},
			},
			{
				Name:                "server",
				CLIName:             "server",
				ModalDisplayName:    "Domain Controller",
				Description:         "DC IP address or hostname",
				ParameterType:       agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:        "",
				DynamicQueryFunction: getActiveHostList,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: true, GroupName: "Default"},
				},
			},
			{
				Name:             "filter",
				CLIName:          "filter",
				ModalDisplayName: "LDAP Filter",
				Description:      "Custom LDAP filter (required when action=query)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "base_dn",
				CLIName:          "base_dn",
				ModalDisplayName: "Base DN",
				Description:      "LDAP search base (auto-detected from RootDSE if empty)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:                 "username",
				CLIName:              "username",
				ModalDisplayName:     "Username",
				Description:          "LDAP bind username (e.g., DOMAIN\\user or user@domain.local). Empty for anonymous bind.",
				ParameterType:        agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:         "",
				DynamicQueryFunction: getCallbackUserList,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "password",
				CLIName:          "password",
				ModalDisplayName: "Password",
				Description:      "LDAP bind password",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "port",
				CLIName:          "port",
				ModalDisplayName: "Port",
				Description:      "LDAP port (default: 389 for LDAP, 636 for LDAPS)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				DefaultValue:     389,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "limit",
				CLIName:          "limit",
				ModalDisplayName: "Result Limit",
				Description:      "Maximum number of results (default: 100)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				DefaultValue:     100,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "use_tls",
				CLIName:          "use_tls",
				ModalDisplayName: "Use LDAPS",
				Description:      "Use TLS/LDAPS (port 636) instead of plain LDAP (port 389)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_BOOLEAN,
				DefaultValue:     false,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "timeout",
				CLIName:          "timeout",
				ModalDisplayName: "Timeout (seconds)",
				Description:      "Operation timeout in seconds (default: 120). Prevents agent hangs on unreachable targets.",
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
			action, _ := taskData.Args.GetStringArg("action")
			server, _ := taskData.Args.GetStringArg("server")
			msg := fmt.Sprintf("OPSEC WARNING: LDAP query (%s) against %s.", action, server)
			switch action {
			case "domain-admins", "admins", "spns", "asrep":
				msg += " Querying privileged/sensitive attributes — may trigger AD honeypot or LDAP monitoring rules for reconnaissance."
			case "dacl":
				msg += " DACL enumeration reads security descriptors — some EDR products monitor bulk DACL reads as BloodHound-like behavior."
			default:
				msg += " LDAP queries generate directory service access logs (Event ID 4662). High-volume queries may trigger anomaly detection."
			}
			return agentstructs.PTTTaskOPSECPreTaskMessageResponse{
				TaskID:             taskData.Task.ID,
				Success:            true,
				OpsecPreBlocked:    false,
				OpsecPreMessage:    msg,
				OpsecPreBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskCompletionFunctions: map[string]agentstructs.PTTaskCompletionFunction{
			"ldapEnumChainComplete": ldapEnumChainCompleteFunc,
		},
		TaskFunctionOPSECPost: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskOPSECPostTaskMessageResponse {
			return agentstructs.PTTaskOPSECPostTaskMessageResponse{
				TaskID:              taskData.Task.ID,
				Success:             true,
				OpsecPostBlocked:    false,
				OpsecPostMessage:    "OPSEC AUDIT: LDAP query executed. LDAP queries logged by domain controllers (Event ID 1644). Bulk enumeration patterns detectable by SIEM correlation rules.",
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
			filter, _ := taskData.Args.GetStringArg("filter")

			// enum-chain: automated AD enumeration (users → groups → trust → kerb-delegation → gpo → adcs)
			if action == "enum-chain" {
				display := fmt.Sprintf("AD Enum Chain on %s (users → groups → trust → delegation → gpo → adcs)", server)
				response.DisplayParams = &display
				completionFunc := "ldapEnumChainComplete"
				response.CompletionFunctionName = &completionFunc

				serverParam := fmt.Sprintf(`"server":"%s"`, server)
				tasks := []mythicrpc.MythicRPCTaskCreateSubtaskGroupTasks{
					{CommandName: "ldap-query", Params: fmt.Sprintf(`{"action":"users",%s}`, serverParam)},
					{CommandName: "ldap-query", Params: fmt.Sprintf(`{"action":"groups",%s}`, serverParam)},
					{CommandName: "trust", Params: fmt.Sprintf(`{"server":"%s"}`, server)},
					{CommandName: "kerb-delegation", Params: fmt.Sprintf(`{"server":"%s"}`, server)},
					{CommandName: "gpo", Params: fmt.Sprintf(`{"server":"%s"}`, server)},
					{CommandName: "adcs", Params: fmt.Sprintf(`{"action":"find","server":"%s"}`, server)},
				}

				groupResult, err := mythicrpc.SendMythicRPCTaskCreateSubtaskGroup(
					mythicrpc.MythicRPCTaskCreateSubtaskGroupMessage{
						TaskID:                taskData.Task.ID,
						GroupName:             "ad_enum_chain",
						GroupCallbackFunction: &completionFunc,
						Tasks:                 tasks,
					},
				)
				if err != nil || !groupResult.Success {
					errMsg := "Failed to create AD enum subtask group"
					if err != nil {
						errMsg = fmt.Sprintf("Failed to create subtask group: %s", err.Error())
					} else if groupResult != nil {
						errMsg = fmt.Sprintf("Failed to create subtask group: %s", groupResult.Error)
					}
					response.Success = false
					response.Error = errMsg
					return response
				}

				createArtifact(taskData.Task.ID, "Subtask Chain",
					fmt.Sprintf("AD Enum Chain on %s: ldap-users + ldap-groups + trust + kerb-delegation + gpo + adcs (parallel)", server))
				return response
			}

			displayMsg := fmt.Sprintf("LDAP %s on %s", action, server)
			if action == "query" && filter != "" {
				displayMsg += fmt.Sprintf(" filter=%s", filter)
			} else if action == "dacl" && filter != "" {
				displayMsg = fmt.Sprintf("LDAP DACL on %s target=%s", server, filter)
			}
			response.DisplayParams = &displayMsg

			mythicrpc.SendMythicRPCArtifactCreate(mythicrpc.MythicRPCArtifactCreateMessage{
				TaskID:           taskData.Task.ID,
				BaseArtifactType: "API Call",
				ArtifactMessage:  fmt.Sprintf("LDAP query: %s on %s", action, server),
			})

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
			server, _ := processResponse.TaskData.Args.GetStringArg("server")

			// Track LDAP queries as Host Discovery artifacts
			if server != "" {
				mythicrpc.SendMythicRPCArtifactCreate(mythicrpc.MythicRPCArtifactCreateMessage{
					TaskID:           processResponse.TaskData.Task.ID,
					BaseArtifactType: "Host Discovery",
					ArtifactMessage:  fmt.Sprintf("LDAP %s query against %s", action, server),
				})
			}

			// Extract host/computer names from output for specific actions
			switch action {
			case "computers":
				for _, line := range strings.Split(responseText, "\n") {
					trimmed := strings.TrimSpace(line)
					if strings.Contains(trimmed, "$") && !strings.HasPrefix(trimmed, "=") && !strings.HasPrefix(trimmed, "-") {
						fields := strings.Fields(trimmed)
						if len(fields) > 0 {
							mythicrpc.SendMythicRPCArtifactCreate(mythicrpc.MythicRPCArtifactCreateMessage{
								TaskID:           processResponse.TaskData.Task.ID,
								BaseArtifactType: "Host Discovery",
								ArtifactMessage:  fmt.Sprintf("AD Computer: %s", fields[0]),
							})
						}
					}
				}
			case "trusts":
				for _, line := range strings.Split(responseText, "\n") {
					trimmed := strings.TrimSpace(line)
					if strings.Contains(trimmed, ".") && !strings.HasPrefix(trimmed, "=") && !strings.HasPrefix(trimmed, "-") && !strings.HasPrefix(trimmed, "Trust") {
						fields := strings.Fields(trimmed)
						if len(fields) > 0 {
							mythicrpc.SendMythicRPCArtifactCreate(mythicrpc.MythicRPCArtifactCreateMessage{
								TaskID:           processResponse.TaskData.Task.ID,
								BaseArtifactType: "Host Discovery",
								ArtifactMessage:  fmt.Sprintf("AD Trust: %s", fields[0]),
							})
						}
					}
				}
			case "gmsa":
				// Register extracted gMSA NTLM hashes in the credential vault
				processGMSACredentials(processResponse.TaskData.Task.ID, responseText, server)
			}
			return response
		},
	})
}

// parseComputerNames extracts AD computer account names from LDAP query output.
func parseComputerNames(responseText string) []string {
	var computers []string
	for _, line := range strings.Split(responseText, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.Contains(trimmed, "$") && !strings.HasPrefix(trimmed, "=") && !strings.HasPrefix(trimmed, "-") {
			fields := strings.Fields(trimmed)
			if len(fields) > 0 {
				computers = append(computers, fields[0])
			}
		}
	}
	return computers
}

// parseTrustDomains extracts AD trust domain names from LDAP query output.
func parseTrustDomains(responseText string) []string {
	var domains []string
	for _, line := range strings.Split(responseText, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.Contains(trimmed, ".") && !strings.HasPrefix(trimmed, "=") && !strings.HasPrefix(trimmed, "-") && !strings.HasPrefix(trimmed, "Trust") {
			fields := strings.Fields(trimmed)
			if len(fields) > 0 {
				domains = append(domains, fields[0])
			}
		}
	}
	return domains
}

// ldapEnumChainCompleteFunc handles subtask completion for the AD enum chain.
var ldapEnumChainCompleteFunc = func(taskData *agentstructs.PTTaskMessageAllData, subtaskData *agentstructs.PTTaskMessageAllData, groupName *agentstructs.SubtaskGroupName) agentstructs.PTTaskCompletionFunctionMessageResponse {
	response := agentstructs.PTTaskCompletionFunctionMessageResponse{
		TaskID:  taskData.Task.ID,
		Success: true,
	}

	parentID := taskData.Task.ID
	searchResult, err := mythicrpc.SendMythicRPCTaskSearch(mythicrpc.MythicRPCTaskSearchMessage{
		TaskID:             parentID,
		SearchParentTaskID: &parentID,
	})

	if err != nil || !searchResult.Success {
		completed := true
		response.Completed = &completed
		summary := "AD Enum Chain completed (could not aggregate results)"
		response.Stdout = &summary
		return response
	}

	var summaryParts []string
	successCount := 0
	errorCount := 0

	for _, task := range searchResult.Tasks {
		status := "unknown"
		if task.Completed {
			if task.Status == "error" {
				status = "ERROR"
				errorCount++
			} else {
				status = "SUCCESS"
				successCount++
			}
		}
		summaryParts = append(summaryParts, fmt.Sprintf("[%s] %s %s", status, task.CommandName, task.DisplayParams))

		// Count result items from each subtask
		respSearch, respErr := mythicrpc.SendMythicRPCResponseSearch(mythicrpc.MythicRPCResponseSearchMessage{
			TaskID: task.ID,
		})
		if respErr == nil && respSearch.Success && len(respSearch.Responses) > 0 {
			for _, resp := range respSearch.Responses {
				text := string(resp.Response)
				lineCount := len(strings.Split(text, "\n"))
				if lineCount > 2 {
					summaryParts = append(summaryParts, fmt.Sprintf("  → %d lines of output", lineCount))
				}
			}
		}
	}

	completed := true
	response.Completed = &completed
	summary := fmt.Sprintf("=== AD Enumeration Chain Complete ===\nSubtasks: %d success, %d errors\n\n%s",
		successCount, errorCount, strings.Join(summaryParts, "\n"))
	response.Stdout = &summary

	mythicrpc.SendMythicRPCResponseCreate(mythicrpc.MythicRPCResponseCreateMessage{
		TaskID:   parentID,
		Response: []byte(summary),
	})

	logging.LogInfo("AD Enum Chain completed", "success", successCount, "errors", errorCount)
	return response
}

// processGMSACredentials parses gMSA output JSON and registers extracted NTLM hashes
// in the Mythic credential vault.
func processGMSACredentials(taskID int, responseText string, server string) {
	var output struct {
		Accounts []struct {
			SAMAccountName string `json:"sAMAccountName"`
			NTLMHash       string `json:"ntlm_hash"`
		} `json:"accounts"`
	}
	if err := json.Unmarshal([]byte(responseText), &output); err != nil {
		return
	}

	var creds []mythicrpc.MythicRPCCredentialCreateCredentialData
	for _, acct := range output.Accounts {
		if acct.NTLMHash == "" {
			continue
		}
		creds = append(creds, mythicrpc.MythicRPCCredentialCreateCredentialData{
			CredentialType: "hash",
			Account:        acct.SAMAccountName,
			Credential:     acct.NTLMHash,
			Realm:          server,
			Comment:        "gMSA NTLM hash extracted via ldap-query gmsa",
		})
		mythicrpc.SendMythicRPCArtifactCreate(mythicrpc.MythicRPCArtifactCreateMessage{
			TaskID:           taskID,
			BaseArtifactType: "Credential Access",
			ArtifactMessage:  fmt.Sprintf("gMSA password extracted: %s", acct.SAMAccountName),
		})
	}
	registerCredentials(taskID, creds)
}
