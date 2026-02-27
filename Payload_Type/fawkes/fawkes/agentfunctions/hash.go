package agentfunctions

import (
	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "hash",
		Description:         "Compute file hashes (MD5, SHA-1, SHA-256, SHA-512). Single files or directories with pattern filtering.",
		HelpString:          "hash -path /etc/passwd\nhash -path C:\\Windows\\System32 -algorithm md5 -pattern *.dll -recursive true\nhash -path /tmp -algorithm sha512 -max_files 100",
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
				Name:             "path",
				CLIName:          "path",
				ModalDisplayName: "File or Directory Path",
				Description:      "Path to file or directory to hash",
				Type:             agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						Required:      true,
						UIModalPosition: 1,
					},
				},
			},
			{
				Name:             "algorithm",
				CLIName:          "algorithm",
				ModalDisplayName: "Hash Algorithm",
				Description:      "Hash algorithm to use",
				Type:             agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				DefaultValue:     "sha256",
				Choices:          []string{"md5", "sha1", "sha256", "sha512"},
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						Required:      false,
						UIModalPosition: 2,
					},
				},
			},
			{
				Name:             "recursive",
				CLIName:          "recursive",
				ModalDisplayName: "Recursive",
				Description:      "Recurse into subdirectories (for directory paths)",
				Type:             agentstructs.COMMAND_PARAMETER_TYPE_BOOLEAN,
				DefaultValue:     false,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						Required:      false,
						UIModalPosition: 3,
					},
				},
			},
			{
				Name:             "pattern",
				CLIName:          "pattern",
				ModalDisplayName: "File Pattern",
				Description:      "Glob pattern to filter files (e.g., *.exe, *.dll)",
				Type:             agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						Required:      false,
						UIModalPosition: 4,
					},
				},
			},
			{
				Name:             "max_files",
				CLIName:          "max_files",
				ModalDisplayName: "Max Files",
				Description:      "Maximum number of files to hash (default: 500)",
				Type:             agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				DefaultValue:     500,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						Required:      false,
						UIModalPosition: 5,
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
	})
}
