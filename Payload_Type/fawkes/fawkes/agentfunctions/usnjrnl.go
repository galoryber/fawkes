package agentfunctions

import (
	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "usn-jrnl",
		Description:         "Query or delete the NTFS USN Change Journal for anti-forensics. Destroys file operation history used in forensic timeline reconstruction.",
		HelpString:          "usn-jrnl -action query\nusn-jrnl -action recent [-volume D:]\nusn-jrnl -action delete [-volume C:]",
		Version:             1,
		SupportedUIFeatures: []string{},
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1070.004"}, // Indicator Removal: File Deletion
		ScriptOnlyCommand:   false,
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_WINDOWS},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:             "action",
				ModalDisplayName: "Action",
				CLIName:          "action",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Description:      "Action: query (show journal metadata), recent (last 100 records), delete (destroy journal)",
				DefaultValue:     "query",
				Choices:          []string{"query", "recent", "delete"},
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: true,
						GroupName:           "Default",
						UIModalPosition:     0,
					},
				},
			},
			{
				Name:             "volume",
				ModalDisplayName: "Volume",
				CLIName:          "volume",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Volume letter (default: C:)",
				DefaultValue:     "C:",
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
			if input != "" {
				return args.LoadArgsFromJSONString(input)
			}
			return nil
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
			volume, _ := taskData.Args.GetStringArg("volume")
			if volume == "" {
				volume = "C:"
			}
			switch action {
			case "delete":
				createArtifact(taskData.Task.ID, "API Call",
					"DeviceIoControl(FSCTL_DELETE_USN_JOURNAL, "+volume+")")
			default:
				createArtifact(taskData.Task.ID, "API Call",
					"DeviceIoControl(FSCTL_QUERY_USN_JOURNAL, "+volume+")")
			}
			if displayParams, err := taskData.Args.GetFinalArgs(); err == nil && displayParams != "" {
				response.DisplayParams = &displayParams
			}
			return response
		},
		TaskFunctionProcessResponse: nil,
	})
}
