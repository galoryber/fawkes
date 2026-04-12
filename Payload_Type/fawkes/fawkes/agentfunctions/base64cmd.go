package agentfunctions

import (
	"fmt"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "base64",
		Description:         "Data encoding toolkit — base64, XOR, hex, ROT13, URL encode, Caesar cipher. Supports string and file I/O.",
		HelpString:          "base64 -action encode -input 'hello world'\nbase64 -action xor -input 'secret data' -key 'mykey'\nbase64 -action xor -input 'secret data' -key 0x41424344\nbase64 -action hex -input /etc/passwd -file true\nbase64 -action hex-decode -input '48656c6c6f'\nbase64 -action rot13 -input 'Hello World'\nbase64 -action url -input 'param=value&foo=bar baz'\nbase64 -action url-decode -input 'hello%20world'\nbase64 -action caesar -input 'Attack at dawn' -shift 3\nbase64 -action caesar -input 'Dwwdfn dw gdzq' -shift -3",
		Version:             2,
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
				Description:      "Encoding algorithm: encode/decode (base64), xor, hex, hex-decode, rot13, url, url-decode, caesar",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				DefaultValue:     "encode",
				Choices:          []string{"encode", "decode", "xor", "hex", "hex-decode", "rot13", "url", "url-decode", "caesar"},
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "input",
				CLIName:          "input",
				ModalDisplayName: "Input",
				Description:      "String to process, or file path if -file is true",
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
			{
				Name:             "key",
				CLIName:          "key",
				ModalDisplayName: "Key",
				Description:      "XOR key — string or hex with 0x prefix (e.g., 'secret' or 0x41424344)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "shift",
				CLIName:          "shift",
				ModalDisplayName: "Shift",
				Description:      "Caesar cipher shift value (1-25, negative to decode)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				DefaultValue:     0,
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
			msg := fmt.Sprintf("OPSEC WARNING: Data encoding — %s (T1140, T1027). ", action)
			if isFile {
				msg += "Reading file contents — file access is logged by EDR. "
			}
			if output != "" {
				msg += "Writing output to file — creates MFT/USN artifacts. "
			}
			if action == "xor" {
				msg += "XOR encoding is commonly associated with malware obfuscation. "
			}
			msg += "Encoding operations may indicate data staging or exfiltration preparation."
			return agentstructs.PTTTaskOPSECPreTaskMessageResponse{
				TaskID: taskData.Task.ID, Success: true,
				OpsecPreBlocked:    false,
				OpsecPreMessage:    msg,
				OpsecPreBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionOPSECPost: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskOPSECPostTaskMessageResponse {
			action, _ := taskData.Args.GetStringArg("action")
			return agentstructs.PTTaskOPSECPostTaskMessageResponse{
				TaskID:              taskData.Task.ID,
				Success:             true,
				OpsecPostBlocked:    false,
				OpsecPostMessage:    fmt.Sprintf("OPSEC AUDIT: Data encoding (%s) completed. No persistent artifacts created.", action),
				OpsecPostBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionCreateTasking: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  taskData.Task.ID,
			}
			action, _ := taskData.Args.GetStringArg("action")
			input, _ := taskData.Args.GetStringArg("input")
			truncated := input
			if len(truncated) > 50 {
				truncated = truncated[:50] + "..."
			}
			display := fmt.Sprintf("%s %s", action, truncated)
			response.DisplayParams = &display
			return response
		},
	})
}
