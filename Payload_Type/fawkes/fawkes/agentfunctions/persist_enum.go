package agentfunctions

import (
	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "persist-enum",
		Description:         "Enumerate common Windows persistence mechanisms — registry Run keys, startup folders, scheduled tasks, services, Winlogon, IFEO, AppInit_DLLs",
		HelpString:          "persist-enum -category all",
		Version:             1,
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1547", "T1053", "T1543"}, // Boot/Logon Autostart, Scheduled Task, Create/Modify System Process
		SupportedUIFeatures: []string{},
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_WINDOWS},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:             "category",
				CLIName:          "category",
				ModalDisplayName: "Category",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Description:      "Which persistence category to enumerate",
				DefaultValue:     "all",
				Choices:          []string{"all", "registry", "startup", "winlogon", "ifeo", "appinit", "tasks", "services"},
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
