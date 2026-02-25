package agentfunctions

import agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "cred-harvest",
		Description:         "Harvest credentials from system files, cloud configs, application secrets, and Windows-specific sources",
		HelpString:          "cred-harvest -action <shadow|cloud|configs|windows|all> [-user <filter>]\nLinux/macOS: shadow, cloud, configs, all\nWindows: cloud, configs, windows, all",
		Version:             2,
		MitreAttackMappings: []string{"T1552.001", "T1552.004", "T1003.008"},
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
				Description:      "shadow: system password hashes (Unix). cloud: cloud/infra credentials. configs: application secrets. windows: PowerShell history, env vars, RDP, WiFi. all: run all platform-appropriate actions.",
				Choices:          []string{"all", "shadow", "cloud", "configs", "windows"},
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

			return response
		},
	})
}
