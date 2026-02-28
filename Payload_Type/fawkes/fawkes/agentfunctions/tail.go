package agentfunctions

import (
	"fmt"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "tail",
		Description:         "Read the first or last N lines (or bytes) of a file without transferring the entire contents.",
		HelpString:          "tail -path /var/log/auth.log\ntail -path /var/log/syslog -lines 50\ntail -path /etc/passwd -head true\ntail -path /tmp/data.bin -bytes 256",
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
				Description:      "Path to the file to read",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: true, GroupName: "Default"},
				},
			},
			{
				Name:             "lines",
				CLIName:          "lines",
				ModalDisplayName: "Number of Lines",
				Description:      "Number of lines to read (default: 10)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				DefaultValue:     10,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "head",
				CLIName:          "head",
				ModalDisplayName: "Read from Beginning",
				Description:      "Read from the beginning of the file instead of the end",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_BOOLEAN,
				DefaultValue:     false,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "bytes",
				CLIName:          "bytes",
				ModalDisplayName: "Number of Bytes",
				Description:      "Read N bytes instead of lines (0 = use lines mode)",
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
		TaskFunctionCreateTasking: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  taskData.Task.ID,
			}
			path, _ := taskData.Args.GetStringArg("path")
			display := fmt.Sprintf("%s", path)
			response.DisplayParams = &display
			return response
		},
	})
}
