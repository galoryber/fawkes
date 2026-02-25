package agentfunctions

import (
	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "grep",
		Description:         "grep -pattern <regex> [-path <dir>] [-extensions .txt,.xml] [-ignore_case] - Search file contents for patterns. Cross-platform recursive file search with regex support.",
		HelpString:          "grep -pattern <regex> [-path <dir>] [-extensions .txt,.xml] [-ignore_case] [-max_results 100] [-context 2] [-max_depth 10]",
		Version:             1,
		MitreAttackMappings: []string{"T1083", "T1552.001"}, // File Discovery + Credentials In Files
		Author:              "@galoryber",
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_LINUX, agentstructs.SUPPORTED_OS_MACOS, agentstructs.SUPPORTED_OS_WINDOWS},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:          "pattern",
				CLIName:       "pattern",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:   "Search pattern (regex supported)",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: true,
						UIModalPosition:     1,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:          "path",
				CLIName:       "path",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:   "File or directory to search (default: current directory)",
				DefaultValue:  ".",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     2,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:          "extensions",
				CLIName:       "extensions",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:   "Filter by file extensions (comma-separated, e.g. .txt,.xml,.config,.ini)",
				DefaultValue:  "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     3,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:          "ignore_case",
				CLIName:       "ignore_case",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_BOOLEAN,
				Description:   "Case-insensitive search",
				DefaultValue:  false,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     4,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:          "max_results",
				CLIName:       "max_results",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				Description:   "Maximum number of results (default: 100)",
				DefaultValue:  100,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     5,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:          "context",
				CLIName:       "context",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				Description:   "Context lines before each match (default: 0)",
				DefaultValue:  0,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     6,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:          "max_depth",
				CLIName:       "max_depth",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				Description:   "Maximum recursion depth (default: 10)",
				DefaultValue:  10,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     7,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:          "max_file_size",
				CLIName:       "max_file_size",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				Description:   "Skip files larger than this (bytes, default: 10485760 = 10MB)",
				DefaultValue:  10485760,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     8,
						GroupName:           "Default",
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
		TaskFunctionCreateTasking: func(task *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  task.Task.ID,
			}
			if displayParams, err := task.Args.GetFinalArgs(); err == nil && displayParams != "" {
				response.DisplayParams = &displayParams
			}
			return response
		},
	})
}
