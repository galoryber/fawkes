package agentfunctions

import (
	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "file-type",
		Description:         "Identify file types by magic bytes (header signatures). Detect executables, archives, documents, images, databases, and encrypted volumes.",
		HelpString:          "file-type -path /tmp/unknown_file\nfile-type -path /home/user/Downloads -recursive true",
		Version:             1,
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1083"},
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{
				agentstructs.SUPPORTED_OS_WINDOWS,
				agentstructs.SUPPORTED_OS_LINUX,
				agentstructs.SUPPORTED_OS_MACOS,
			},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:          "path",
				CLIName:       "path",
				Description:   "Path to file or directory to analyze",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: true, GroupName: "Default"},
				},
			},
			{
				Name:          "recursive",
				CLIName:       "recursive",
				Description:   "Recursively analyze directory contents",
				DefaultValue:  false,
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_BOOLEAN,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:          "max_files",
				CLIName:       "max_files",
				Description:   "Maximum number of files to analyze in directory mode (default: 100)",
				DefaultValue:  100,
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
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
			return agentstructs.PTTaskCreateTaskingMessageResponse{Success: true, TaskID: taskData.Task.ID}
		},
	})
}
