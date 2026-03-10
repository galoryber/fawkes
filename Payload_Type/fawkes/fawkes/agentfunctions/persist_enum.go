package agentfunctions

import (
	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "persist-enum",
		Description:         "Enumerate persistence mechanisms — Windows: registry, startup, tasks, services. Linux: cron, systemd, shell profiles, SSH keys. macOS: LaunchAgents, login items, periodic scripts.",
		HelpString:          "persist-enum -category all\n\nCategories by platform:\n  Windows: all, registry, startup, winlogon, ifeo, appinit, tasks, services\n  Linux: all, cron, systemd, shell, startup, ssh, preload\n  macOS: all, launchd, cron, shell, login, periodic",
		Version:             2,
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1547", "T1053", "T1543"}, // Boot/Logon Autostart, Scheduled Task, Create/Modify System Process
		SupportedUIFeatures: []string{},
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_WINDOWS, agentstructs.SUPPORTED_OS_LINUX, agentstructs.SUPPORTED_OS_MACOS},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:             "category",
				CLIName:          "category",
				ModalDisplayName: "Category",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Which persistence category to enumerate (default: all). Platform-specific categories — see help.",
				DefaultValue:     "all",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
						UIModalPosition:     1,
					},
				},
			},
		},
		TaskFunctionParseArgString: func(args *agentstructs.PTTaskMessageArgsData, input string) error {
			if input == "" {
				input = "{}"
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

			category, _ := taskData.Args.GetStringArg("category")
			if category == "" {
				category = "all"
			}
			displayParams := "category: " + category
			response.DisplayParams = &displayParams

			return response
		},
	})
}
