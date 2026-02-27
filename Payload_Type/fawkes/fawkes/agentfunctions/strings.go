package agentfunctions

import (
	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "strings",
		Description:         "Extract printable strings from files. Find embedded text, URLs, credentials in binaries.",
		HelpString:          "strings -path /tmp/payload.bin\nstrings -path C:\\Windows\\System32\\cmd.exe -min_length 8\nstrings -path /usr/bin/ssh -pattern http\nstrings -path malware.exe -min_length 6 -pattern password",
		Version:             1,
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1005", "T1083"},
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{
				agentstructs.SUPPORTED_OS_WINDOWS,
				agentstructs.SUPPORTED_OS_LINUX,
				agentstructs.SUPPORTED_OS_MACOS,
			},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:             "path",
				CLIName:          "path",
				ModalDisplayName: "File Path",
				Description:      "Path to file to extract strings from",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: true, GroupName: "Default"},
				},
			},
			{
				Name:             "min_length",
				CLIName:          "min_length",
				ModalDisplayName: "Minimum String Length",
				Description:      "Minimum length of printable strings to extract (default: 4)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				DefaultValue:     4,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "offset",
				CLIName:          "offset",
				ModalDisplayName: "Byte Offset",
				Description:      "Starting byte offset (default: 0)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				DefaultValue:     0,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "max_size",
				CLIName:          "max_size",
				ModalDisplayName: "Max Scan Size",
				Description:      "Maximum bytes to scan (default: 10MB)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				DefaultValue:     10485760,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "pattern",
				CLIName:          "pattern",
				ModalDisplayName: "Filter Pattern",
				Description:      "Only show strings containing this text (case-insensitive)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:     "",
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
			return agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  taskData.Task.ID,
			}
		},
	})
}
