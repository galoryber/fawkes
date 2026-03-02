package agentfunctions

import agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "ide-recon",
		Description:         "Enumerate IDE configurations — VS Code and JetBrains extensions, remote SSH hosts, recent projects, data sources, and secrets",
		HelpString:          "ide-recon -action <vscode|jetbrains|all> [-user <filter>]",
		Version:             1,
		SupportedUIFeatures: []string{},
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1005", "T1083"},
		ScriptOnlyCommand:   false,
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{
				agentstructs.SUPPORTED_OS_WINDOWS,
				agentstructs.SUPPORTED_OS_LINUX,
				agentstructs.SUPPORTED_OS_MACOS,
			},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:             "action",
				ModalDisplayName: "Action",
				CLIName:          "action",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Description:      "vscode: VS Code settings, extensions, remote SSH, recent projects. jetbrains: IntelliJ/PyCharm/GoLand configs, data sources, deployment servers. all: scan both.",
				Choices:          []string{"all", "vscode", "jetbrains"},
				DefaultValue:     "all",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: true, GroupName: "Default", UIModalPosition: 0},
				},
			},
			{
				Name:             "user",
				ModalDisplayName: "User Filter",
				CLIName:          "user",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Target specific user's home directory (optional, defaults to current user)",
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

			return response
		},
	})
}
