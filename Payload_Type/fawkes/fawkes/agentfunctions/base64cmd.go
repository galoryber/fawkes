package agentfunctions

import (
	"fmt"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "base64",
		Description:         "Encode or decode base64 — strings and files, with optional output to file.",
		HelpString:          "base64 -action encode -input 'hello world'\nbase64 -action encode -input /etc/passwd -file true\nbase64 -action decode -input 'SGVsbG8=' -output /tmp/decoded.bin",
		Version:             1,
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1132.001", "T1027", "T1140"},
		SupportedUIFeatures: []string{"file_browser:download"},
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{
				agentstructs.SUPPORTED_OS_WINDOWS,
				agentstructs.SUPPORTED_OS_LINUX,
				agentstructs.SUPPORTED_OS_MACOS,
			},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:             "action",
				CLIName:          "action",
				ModalDisplayName: "Action",
				Description:      "encode or decode",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				DefaultValue:     "encode",
				Choices:          []string{"encode", "decode"},
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "input",
				CLIName:          "input",
				ModalDisplayName: "Input",
				Description:      "String to encode/decode, or file path if -file is true",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: true, GroupName: "Default"},
				},
			},
			{
				Name:             "file",
				CLIName:          "file",
				ModalDisplayName: "Input is File Path",
				Description:      "Treat input as a file path to read from",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_BOOLEAN,
				DefaultValue:     false,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "output",
				CLIName:          "output",
				ModalDisplayName: "Output File",
				Description:      "Write result to file instead of displaying (optional)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
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
		TaskFunctionOPSECPre: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTTaskOPSECPreTaskMessageResponse {
			action, _ := taskData.Args.GetStringArg("action")
			isFile, _ := taskData.Args.GetBooleanArg("file")
			output, _ := taskData.Args.GetStringArg("output")
			msg := fmt.Sprintf("OPSEC WARNING: Base64 %s (T1132.001, T1027). ", action)
			if isFile {
				msg += "Reading file contents for encoding — file access is logged by EDR. "
			}
			if output != "" {
				msg += "Writing output to file — creates MFT/USN artifacts. "
			}
			msg += "Base64 operations are commonly associated with obfuscation and data staging."
			return agentstructs.PTTTaskOPSECPreTaskMessageResponse{
				TaskID: taskData.Task.ID, Success: true,
				OpsecPreBlocked:    false,
				OpsecPreMessage:    msg,
				OpsecPreBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionCreateTasking: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  taskData.Task.ID,
			}
			action, _ := taskData.Args.GetStringArg("action")
			input, _ := taskData.Args.GetStringArg("input")
			display := fmt.Sprintf("%s %s", action, input)
			response.DisplayParams = &display
			return response
		},
	})
}
