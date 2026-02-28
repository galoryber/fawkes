package agentfunctions

import (
	"fmt"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "encrypt",
		Description:         "Encrypt or decrypt files using AES-256-GCM for secure data staging before exfiltration.",
		HelpString:          "encrypt -action encrypt -path /tmp/data.tar.gz\nencrypt -action decrypt -path /tmp/data.tar.gz.enc -key <base64key>",
		Version:             1,
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1560.001"},
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{
				agentstructs.SUPPORTED_OS_WINDOWS,
				agentstructs.SUPPORTED_OS_LINUX,
				agentstructs.SUPPORTED_OS_MACOS,
			},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:          "action",
				CLIName:       "action",
				Description:   "Action to perform: encrypt or decrypt",
				DefaultValue:  "encrypt",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:       []string{"encrypt", "decrypt"},
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: true,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:          "path",
				CLIName:       "path",
				Description:   "Path to the file to encrypt/decrypt",
				DefaultValue:  "",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: true,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:          "output",
				CLIName:       "output",
				Description:   "Output file path (default: input path + .enc for encrypt, - .enc for decrypt)",
				DefaultValue:  "",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:          "key",
				CLIName:       "key",
				Description:   "Base64-encoded AES-256 key (auto-generated for encrypt if not provided, required for decrypt)",
				DefaultValue:  "",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
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
			action, _ := taskData.Args.GetStringArg("action")
			path, _ := taskData.Args.GetStringArg("path")
			display := fmt.Sprintf("%s %s", action, path)
			response.DisplayParams = &display
			createArtifact(taskData.Task.ID, "File Write", fmt.Sprintf("File encryption of %s", path))
			return response
		},
	})
}
