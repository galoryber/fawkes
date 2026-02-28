package agentfunctions

import (
	"path/filepath"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "handles",
		Description:         "handles -pid <pid> [-type File] [-show_names] [-max_count 500] - Enumerate open handles in a target process. Windows-only using NtQuerySystemInformation.",
		HelpString:          "handles -pid <pid> [-type File] [-show_names] [-max_count 500]",
		Version:             1,
		MitreAttackMappings: []string{"T1057", "T1082"}, // Process Discovery + System Information Discovery
		Author:              "@galoryber",
		AssociatedBrowserScript: &agentstructs.BrowserScript{
			ScriptPath: filepath.Join(".", "fawkes", "browserscripts", "handles_new.js"),
			Author:     "@galoryber",
		},
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_WINDOWS},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:          "pid",
				CLIName:       "pid",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				Description:   "Target process ID to enumerate handles for",
				DefaultValue:  0,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: true,
						UIModalPosition:     1,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:          "type",
				CLIName:       "type",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:   "Filter by handle type (e.g. File, Key, Section, Mutant, Event, Process, Thread)",
				DefaultValue:  "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     2,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:          "show_names",
				CLIName:       "show_names",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_BOOLEAN,
				Description:   "Resolve handle names (slower but more detailed)",
				DefaultValue:  false,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     3,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:          "max_count",
				CLIName:       "max_count",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				Description:   "Maximum handles to enumerate (default: 500)",
				DefaultValue:  500,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     4,
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
			createArtifact(task.Task.ID, "API Call", "NtQuerySystemInformation(SystemHandleInformation) + NtQueryObject")
			if displayParams, err := task.Args.GetFinalArgs(); err == nil && displayParams != "" {
				response.DisplayParams = &displayParams
			}
			return response
		},
	})
}
