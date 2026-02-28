package agentfunctions

import (
	"fmt"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "xattr",
		Description:         "Manage extended file attributes — list, get, set, delete. Unix complement to Windows ADS for hiding data in file metadata. Supports text and hex-encoded binary values.",
		HelpString:          "xattr -path /tmp/file.txt\nxattr -action get -path /tmp/file.txt -name user.secret\nxattr -action set -path /tmp/file.txt -name user.hidden -value 'secret data'\nxattr -action set -path /tmp/file.txt -name user.bin -value 48656c6c6f -hex true\nxattr -action delete -path /tmp/file.txt -name user.hidden",
		Version:             1,
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1564.004"},
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{
				agentstructs.SUPPORTED_OS_LINUX,
				agentstructs.SUPPORTED_OS_MACOS,
			},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:          "action",
				CLIName:       "action",
				Description:   "Action to perform: list, get, set, delete (default: list)",
				DefaultValue:  "list",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:          "path",
				CLIName:       "path",
				Description:   "Target file path",
				DefaultValue:  "",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: true, GroupName: "Default"},
				},
			},
			{
				Name:          "name",
				CLIName:       "name",
				Description:   "Attribute name (e.g., user.secret). Required for get, set, delete.",
				DefaultValue:  "",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:          "value",
				CLIName:       "value",
				Description:   "Value to set (text or hex-encoded if -hex true)",
				DefaultValue:  "",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:          "hex",
				CLIName:       "hex",
				Description:   "Treat value as hex-encoded binary (default: false)",
				DefaultValue:  false,
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_BOOLEAN,
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
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  taskData.Task.ID,
			}
			action, _ := taskData.Args.GetStringArg("action")
			path, _ := taskData.Args.GetStringArg("path")
			display := fmt.Sprintf("%s %s", action, path)
			response.DisplayParams = &display
			return response
		},
	})
}
