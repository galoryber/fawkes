package agentfunctions

import (
	"fmt"
	"strings"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "find",
		Description:         "Search for files by name pattern with optional size, date, and type filters",
		HelpString:          "find -path <dir> -pattern <glob> [-min_size <bytes>] [-max_size <bytes>] [-newer <minutes>] [-older <minutes>] [-type f|d]",
		Version:             2,
		SupportedUIFeatures: []string{},
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1083"},
		ScriptOnlyCommand:   false,
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_LINUX, agentstructs.SUPPORTED_OS_MACOS, agentstructs.SUPPORTED_OS_WINDOWS},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:             "path",
				ModalDisplayName: "Search Path",
				CLIName:          "path",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Directory to search in (default: current directory)",
				DefaultValue:     ".",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "pattern",
				ModalDisplayName: "File Pattern",
				CLIName:          "pattern",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Glob pattern to match filenames (e.g. *.txt, *.conf, password*). Defaults to * when filters are set.",
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "max_depth",
				ModalDisplayName: "Max Depth",
				CLIName:          "max_depth",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				Description:      "Maximum directory depth to search (default: 10)",
				DefaultValue:     10,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "min_size",
				ModalDisplayName: "Min Size (bytes)",
				CLIName:          "min_size",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				Description:      "Minimum file size in bytes (0 = no minimum)",
				DefaultValue:     0,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "max_size",
				ModalDisplayName: "Max Size (bytes)",
				CLIName:          "max_size",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				Description:      "Maximum file size in bytes (0 = no maximum)",
				DefaultValue:     0,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "newer",
				ModalDisplayName: "Newer Than (min)",
				CLIName:          "newer",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				Description:      "Only files modified within the last N minutes (0 = no filter)",
				DefaultValue:     0,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "older",
				ModalDisplayName: "Older Than (min)",
				CLIName:          "older",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				Description:      "Only files modified more than N minutes ago (0 = no filter)",
				DefaultValue:     0,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "type",
				ModalDisplayName: "Type Filter",
				CLIName:          "type",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Filter by type: 'f' for files only, 'd' for directories only (empty = both)",
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
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
			path, _ := taskData.Args.GetStringArg("path")
			pattern, _ := taskData.Args.GetStringArg("pattern")
			minSize, _ := taskData.Args.GetNumberArg("min_size")
			maxSize, _ := taskData.Args.GetNumberArg("max_size")
			newer, _ := taskData.Args.GetNumberArg("newer")
			older, _ := taskData.Args.GetNumberArg("older")
			typeFilter, _ := taskData.Args.GetStringArg("type")

			display := fmt.Sprintf("%s %s", path, pattern)
			var filters []string
			if minSize > 0 {
				filters = append(filters, fmt.Sprintf("min_size=%d", int(minSize)))
			}
			if maxSize > 0 {
				filters = append(filters, fmt.Sprintf("max_size=%d", int(maxSize)))
			}
			if newer > 0 {
				filters = append(filters, fmt.Sprintf("newer=%dm", int(newer)))
			}
			if older > 0 {
				filters = append(filters, fmt.Sprintf("older=%dm", int(older)))
			}
			if typeFilter != "" {
				filters = append(filters, fmt.Sprintf("type=%s", typeFilter))
			}
			if len(filters) > 0 {
				display += " (" + strings.Join(filters, ", ") + ")"
			}
			response.DisplayParams = &display
			return response
		},
	})
}
