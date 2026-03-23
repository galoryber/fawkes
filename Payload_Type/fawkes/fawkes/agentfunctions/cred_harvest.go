package agentfunctions

import agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"

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
