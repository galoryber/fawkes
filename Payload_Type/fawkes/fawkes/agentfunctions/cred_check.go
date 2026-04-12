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
		Name:                "cred-check",
		Description:         "Test credentials against SMB, WinRM, and LDAP on target hosts. Use 'verify-all' action to test all credentials from the vault against discovered hosts.",
		HelpString:          "cred-check -hosts <IPs/CIDRs> -username <DOMAIN\\user> -password <pass> [-hash <NTLM>] [-timeout <seconds>]\ncred-check -action verify-all",
		Version:             2,
		SupportedUIFeatures: []string{},
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1110.001", "T1078"},
		ScriptOnlyCommand:   false,
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_LINUX, agentstructs.SUPPORTED_OS_MACOS, agentstructs.SUPPORTED_OS_WINDOWS},
		},
		TaskCompletionFunctions: map[string]agentstructs.PTTaskCompletionFunction{
			"credVerifyAllDone": credVerifyAllDone,
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:             "action",
				CLIName:          "action",
				ModalDisplayName: "Action",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:          []string{"check", "verify-all"},
				Description:      "check: test specific credentials. verify-all: test all vault credentials against discovered hosts.",
				DefaultValue:     "check",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:                 "hosts",
				ModalDisplayName:     "Target Hosts",
				CLIName:              "hosts",
				ParameterType:        agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:          "Single IP, comma-separated IPs, or CIDR range. Max 256 hosts.",
				DefaultValue:         "",
				DynamicQueryFunction: getActiveHostList,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:                 "username",
				ModalDisplayName:     "Username",
				CLIName:              "username",
				ParameterType:        agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:          "Username (DOMAIN\\user or user@domain)",
				DefaultValue:         "",
				DynamicQueryFunction: getCallbackUserList,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "password",
				ModalDisplayName: "Password",
				CLIName:          "password",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Password (or use -hash for pass-the-hash on SMB)",
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "hash",
				ModalDisplayName: "NTLM Hash",
				CLIName:          "hash",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "NTLM hash for pass-the-hash (SMB only, hex-encoded NT hash or LM:NT format)",
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "timeout",
				ModalDisplayName: "Timeout (seconds)",
				CLIName:          "timeout",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				Description:      "Per-check timeout in seconds (default: 5)",
				DefaultValue:     5,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
		},
		AssociatedBrowserScript: &agentstructs.BrowserScript{ScriptPath: filepath.Join(".", "fawkes", "browserscripts", "cred_check_new.js"), Author: "@galoryber"},
		TaskFunctionOPSECPre: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTTaskOPSECPreTaskMessageResponse {
			hosts, _ := taskData.Args.GetStringArg("hosts")
			return agentstructs.PTTTaskOPSECPreTaskMessageResponse{
				TaskID: taskData.Task.ID, Success: true,
				OpsecPreBlocked:    false,
				OpsecPreMessage:    fmt.Sprintf("OPSEC WARNING: Testing credentials against %s via SMB/WinRM/LDAP (T1110.001). Failed auth attempts generate Event ID 4625 (Logon Failure). Multiple failures may trigger account lockout policies.", hosts),
				OpsecPreBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionOPSECPost: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskOPSECPostTaskMessageResponse {
			return agentstructs.PTTaskOPSECPostTaskMessageResponse{
				TaskID:              taskData.Task.ID,
				Success:             true,
				OpsecPostBlocked:    false,
				OpsecPostMessage:    "OPSEC AUDIT: Credential validation completed. Failed authentication attempts generate Event ID 4625 (Logon Failure) on target hosts. Successful auths generate Event ID 4624. Multiple failures may have triggered account lockout policies. Review target host Security event logs for forensic artifacts.",
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
			if action == "verify-all" {
				return credCheckVerifyAll(taskData)
			}

			hosts, _ := taskData.Args.GetStringArg("hosts")
			username, _ := taskData.Args.GetStringArg("username")
			if hosts == "" || username == "" {
				response.Success = false
				response.Error = "hosts and username are required for check action"
				return response
			}
			display := fmt.Sprintf("hosts: %s, user: %s", hosts, username)
			response.DisplayParams = &display
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
			// Track successful authentications as artifacts
			for _, line := range strings.Split(responseText, "\n") {
				if strings.Contains(line, "SUCCESS") && strings.Contains(line, "|") {
					parts := strings.Split(line, "|")
					if len(parts) >= 3 {
						host := strings.TrimSpace(parts[0])
						protocol := strings.TrimSpace(parts[1])
						createArtifact(processResponse.TaskData.Task.ID, "Network Connection",
							fmt.Sprintf("Credential check SUCCESS: %s via %s", host, protocol))
					}
				}
			}
			return response
		},
	})
}

// credCheckVerifyAll queries the credential vault and active hosts,
// then creates parallel cred-check subtasks for each testable credential.
func credCheckVerifyAll(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
	response := agentstructs.PTTaskCreateTaskingMessageResponse{
		Success: true,
		TaskID:  taskData.Task.ID,
	}

	// 1. Get all credentials from vault
	credResp, err := mythicrpc.SendMythicRPCCredentialSearch(mythicrpc.MythicRPCCredentialSearchMessage{
		TaskID:            taskData.Task.ID,
		SearchCredentials: mythicrpc.MythicRPCCredentialSearchCredentialData{},
	})
	if err != nil || !credResp.Success {
		response.Success = false
		response.Error = "Failed to query credential vault"
		return response
	}
	if len(credResp.Credentials) == 0 {
		response.Success = false
		response.Error = "No credentials in vault. Run credential harvesting commands first."
		return response
	}

	// 2. Get active hosts from callbacks
	cbResp, err := mythicrpc.SendMythicRPCCallbackSearch(mythicrpc.MythicRPCCallbackSearchMessage{
		AgentCallbackID: taskData.Callback.AgentCallbackID,
	})
	if err != nil || !cbResp.Success {
		response.Success = false
		response.Error = "Failed to query active callbacks for host list"
		return response
	}
	seen := make(map[string]bool)
	var hosts []string
	for _, cb := range cbResp.Results {
		if !cb.Active || cb.Ip == "" {
			continue
		}
		if !seen[cb.Ip] {
			seen[cb.Ip] = true
			hosts = append(hosts, cb.Ip)
		}
	}
	if len(hosts) == 0 {
		response.Success = false
		response.Error = "No active callback hosts found for testing"
		return response
	}
	hostList := strings.Join(hosts, ",")

	// 3. Filter to testable credentials (plaintext or hash)
	type testCred struct {
		account  string
		realm    string
		password string
		hash     string
	}
	var creds []testCred
	credSeen := make(map[string]bool)
	for _, c := range credResp.Credentials {
		if c.Account == nil || *c.Account == "" {
			continue
		}
		if c.Credential == nil || *c.Credential == "" {
			continue
		}
		credType := ""
		if c.Type != nil {
			credType = *c.Type
		}
		// Only test plaintext passwords and NTLM hashes
		if credType != "plaintext" && credType != "hash" {
			continue
		}
		account := *c.Account
		realm := ""
		if c.Realm != nil {
			realm = *c.Realm
		}
		key := account + "|" + realm + "|" + credType
		if credSeen[key] {
			continue
		}
		credSeen[key] = true

		tc := testCred{account: account, realm: realm}
		if credType == "plaintext" {
			tc.password = *c.Credential
		} else {
			tc.hash = *c.Credential
		}
		creds = append(creds, tc)
	}

	if len(creds) == 0 {
		response.Success = false
		response.Error = "No testable credentials (plaintext/hash) in vault"
		return response
	}

	// Cap at 10 to avoid excessive network traffic
	if len(creds) > 10 {
		creds = creds[:10]
	}

	// 4. Create parallel subtask group
	var tasks []mythicrpc.MythicRPCTaskCreateSubtaskGroupTasks
	for _, c := range creds {
		username := c.account
		if c.realm != "" {
			username = c.realm + "\\" + c.account
		}
		params := map[string]interface{}{
			"action":   "check",
			"hosts":    hostList,
			"username": username,
			"timeout":  5,
		}
		if c.password != "" {
			params["password"] = c.password
		}
		if c.hash != "" {
			params["hash"] = c.hash
		}
		paramsJSON, _ := json.Marshal(params)
		tasks = append(tasks, mythicrpc.MythicRPCTaskCreateSubtaskGroupTasks{
			CommandName: "cred-check",
			Params:      string(paramsJSON),
		})
	}

	completionFunc := "credVerifyAllDone"
	response.CompletionFunctionName = &completionFunc

	groupResult, err := mythicrpc.SendMythicRPCTaskCreateSubtaskGroup(
		mythicrpc.MythicRPCTaskCreateSubtaskGroupMessage{
			TaskID:                taskData.Task.ID,
			GroupName:             "cred_verify_all",
			GroupCallbackFunction: &completionFunc,
			Tasks:                 tasks,
		},
	)
	if err != nil || !groupResult.Success {
		errMsg := "Failed to create subtask group"
		if err != nil {
			errMsg = fmt.Sprintf("Failed to create subtask group: %v", err)
		}
		response.Success = false
		response.Error = errMsg
		return response
	}

	display := fmt.Sprintf("Verify All: %d credentials against %d hosts", len(creds), len(hosts))
	response.DisplayParams = &display

	createArtifact(taskData.Task.ID, "Subtask Chain",
		fmt.Sprintf("Credential Verification: testing %d vault credentials against %s", len(creds), hostList))

	return response
}

// credVerifyAllDone aggregates results from parallel cred-check subtasks.
func credVerifyAllDone(
	taskData *agentstructs.PTTaskMessageAllData,
	subtaskData *agentstructs.PTTaskMessageAllData,
	_ *agentstructs.SubtaskGroupName,
) agentstructs.PTTaskCompletionFunctionMessageResponse {
	response := agentstructs.PTTaskCompletionFunctionMessageResponse{
		TaskID:  taskData.Task.ID,
		Success: true,
	}

	// Search for all subtasks
	parentID := taskData.Task.ID
	searchResult, err := mythicrpc.SendMythicRPCTaskSearch(mythicrpc.MythicRPCTaskSearchMessage{
		TaskID:             parentID,
		SearchParentTaskID: &parentID,
	})

	summary := "=== Credential Verification Summary ===\n"
	validCount := 0
	failedCount := 0
	errorCount := 0

	if err == nil && searchResult.Success {
		for _, task := range searchResult.Tasks {
			// Get each subtask's output to count success/failure
			output := getSubtaskResponses(task.ID)
			successes := strings.Count(output, "SUCCESS")
			failures := strings.Count(output, "FAILED")

			status := "?"
			if task.Status == "error" {
				status = "ERROR"
				errorCount++
			} else if successes > 0 {
				status = fmt.Sprintf("VALID (%d)", successes)
				validCount++
			} else {
				status = fmt.Sprintf("INVALID (%d failed)", failures)
				failedCount++
			}
			summary += fmt.Sprintf("  [%s] %s\n", status, task.DisplayParams)
		}
	}

	summary += fmt.Sprintf("\nResults: %d valid, %d invalid, %d errors (out of %d credentials)\n",
		validCount, failedCount, errorCount, validCount+failedCount+errorCount)

	completed := true
	response.Completed = &completed
	response.Stdout = &summary

	mythicrpc.SendMythicRPCResponseCreate(mythicrpc.MythicRPCResponseCreateMessage{
		TaskID:   taskData.Task.ID,
		Response: []byte(summary),
	})

	logOperationEvent(taskData.Task.ID,
		fmt.Sprintf("[CREDENTIAL] Verify-all complete on %s: %d valid, %d invalid, %d errors",
			taskData.Callback.Host, validCount, failedCount, errorCount), false)

	return response
}

// credCheckSuccessResult represents a parsed success line from cred-check output.
type credCheckSuccessResult struct {
	Host     string
	Protocol string
}

// parseCredCheckSuccesses extracts successful credential check results from output text.
// Looks for lines containing "SUCCESS" and "|" delimiter, parsing host|protocol|status.
func parseCredCheckSuccesses(text string) []credCheckSuccessResult {
	var results []credCheckSuccessResult
	for _, line := range strings.Split(text, "\n") {
		if !strings.Contains(line, "SUCCESS") || !strings.Contains(line, "|") {
			continue
		}
		parts := strings.Split(line, "|")
		if len(parts) >= 3 {
			results = append(results, credCheckSuccessResult{
				Host:     strings.TrimSpace(parts[0]),
				Protocol: strings.TrimSpace(parts[1]),
			})
		}
	}
	return results
}
