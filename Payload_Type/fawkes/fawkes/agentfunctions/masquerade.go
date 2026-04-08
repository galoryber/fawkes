package agentfunctions

import (
	"fmt"
	"strings"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "masquerade",
		Description:         "File masquerading — copy or rename files with deceptive names to evade detection. Supports double extensions, RtL override, trailing spaces, and process name matching.",
		HelpString:          "masquerade -source payload.exe -technique double_ext -disguise document.pdf\nmasquerade -source payload.exe -technique rtlo -disguise txt\nmasquerade -source payload.exe -technique space -disguise txt\nmasquerade -source payload.exe -technique process -disguise svchost\nmasquerade -source payload.exe -technique match_ext -disguise txt -in_place true",
		Version:             1,
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1036", "T1036.007", "T1036.005"},
		SupportedUIFeatures: []string{},
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{
				agentstructs.SUPPORTED_OS_WINDOWS,
				agentstructs.SUPPORTED_OS_LINUX,
				agentstructs.SUPPORTED_OS_MACOS,
			},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:          "source",
				CLIName:       "source",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:   "Path to the file to masquerade",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: true,
						UIModalPosition:     1,
						GroupName:            "Default",
					},
				},
			},
			{
				Name:          "technique",
				CLIName:       "technique",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:       []string{"double_ext", "rtlo", "space", "process", "match_ext"},
				Description:   "Masquerade technique: double_ext (doc.pdf.exe), rtlo (Unicode reverse), space (trailing spaces), process (match OS process names), match_ext (change extension)",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: true,
						UIModalPosition:     2,
						GroupName:            "Default",
					},
				},
			},
			{
				Name:          "disguise",
				CLIName:       "disguise",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:  "",
				Description:   "Disguise value — varies by technique: fake filename (double_ext), extension (rtlo/space/match_ext), process name (process). Defaults provided if empty.",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     3,
						GroupName:            "Default",
					},
				},
			},
			{
				Name:          "in_place",
				CLIName:       "in_place",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_BOOLEAN,
				DefaultValue:  false,
				Description:   "Rename in-place (true) or create a copy (false, default)",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     4,
						GroupName:            "Default",
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
		TaskFunctionOPSECPre: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTTaskOPSECPreTaskMessageResponse {
			technique, _ := taskData.Args.GetStringArg("technique")
			msg := fmt.Sprintf("OPSEC WARNING: File masquerading using technique '%s' (T1036). Creating deceptively named files may trigger endpoint detection if the original filename is known. RtLO characters are flagged by some EDR products.", technique)
			return agentstructs.PTTTaskOPSECPreTaskMessageResponse{
				TaskID: taskData.Task.ID, Success: true,
				OpsecPreBlocked: false, OpsecPreMessage: msg,
				OpsecPreBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionCreateTasking: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  taskData.Task.ID,
			}
			source, _ := taskData.Args.GetStringArg("source")
			technique, _ := taskData.Args.GetStringArg("technique")
			display := fmt.Sprintf("%s → %s", source, technique)
			response.DisplayParams = &display
			return response
		},
		TaskFunctionProcessResponse: func(processResponse agentstructs.PtTaskProcessResponseMessage) agentstructs.PTTaskProcessResponseMessageResponse {
			response := agentstructs.PTTaskProcessResponseMessageResponse{
				TaskID:  processResponse.TaskData.Task.ID,
				Success: true,
			}
			responseText, ok := processResponse.Response.(string)
			if !ok || responseText == "" {
				return response
			}
			if strings.Contains(responseText, "success") || strings.Contains(responseText, "Success") {
				technique, _ := processResponse.TaskData.Args.GetStringArg("technique")
				createArtifact(processResponse.TaskData.Task.ID, "File Modify",
					fmt.Sprintf("File masquerade applied: %s (T1036)", technique))
			}
			return response
		},
	})
}
