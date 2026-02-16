package agentfunctions

import (
	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "timestomp",
		Description:         "Modify file timestamps to blend in with surrounding files",
		HelpString:          "timestomp -action get -target C:\\path\\file.txt\ntimestomp -action copy -target C:\\path\\file.txt -source C:\\Windows\\System32\\notepad.exe\ntimestomp -action set -target C:\\path\\file.txt -timestamp 2024-01-15T10:30:00Z",
		Version:             1,
		MitreAttackMappings: []string{"T1070.006"}, // Indicator Removal: Timestomp
		SupportedUIFeatures: []string{},
		Author:              "@galoryber",
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_LINUX, agentstructs.SUPPORTED_OS_MACOS, agentstructs.SUPPORTED_OS_WINDOWS},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:          "action",
				CLIName:       "action",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Description:   "Action to perform: get (show timestamps), copy (from another file), set (specific time)",
				Choices:       []string{"get", "copy", "set"},
				DefaultValue:  "get",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: true,
						GroupName:           "Default",
						UIModalPosition:     0,
					},
				},
			},
			{
				Name:          "target",
				CLIName:       "target",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:   "Target file to modify or read timestamps from",
				DefaultValue:  "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: true,
						GroupName:           "Default",
						UIModalPosition:     1,
					},
				},
			},
			{
				Name:          "source",
				CLIName:       "source",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:   "Source file to copy timestamps from (for 'copy' action)",
				DefaultValue:  "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
						UIModalPosition:     2,
					},
				},
			},
			{
				Name:          "timestamp",
				CLIName:       "timestamp",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:   "Timestamp to set (for 'set' action). Formats: 2024-01-15T10:30:00Z, 2024-01-15 10:30:00, 2024-01-15, 01/15/2024",
				DefaultValue:  "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
						UIModalPosition:     3,
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
		TaskFunctionCreateTasking: func(task *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  task.Task.ID,
			}

			action, _ := task.Args.GetStringArg("action")
			target, _ := task.Args.GetStringArg("target")
			source, _ := task.Args.GetStringArg("source")
			timestamp, _ := task.Args.GetStringArg("timestamp")

			displayParams := action + " " + target
			if source != "" {
				displayParams += " (from: " + source + ")"
			}
			if timestamp != "" {
				displayParams += " (time: " + timestamp + ")"
			}
			response.DisplayParams = &displayParams

			return response
		},
	})
}
