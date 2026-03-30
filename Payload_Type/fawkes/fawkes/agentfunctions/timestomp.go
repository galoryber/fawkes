package agentfunctions

import (
	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "timestomp",
		Description:         "Modify file timestamps to blend in with surrounding files",
		HelpString:          "timestomp -action get -target C:\\path\\file.txt\ntimestomp -action copy -target C:\\path\\file.txt -source C:\\Windows\\System32\\notepad.exe\ntimestomp -action set -target C:\\path\\file.txt -timestamp 2024-01-15T10:30:00Z\ntimestomp -action match -target C:\\path\\file.txt\ntimestomp -action random -target C:\\path\\file.txt -source 2023-01-01 -timestamp 2024-06-15",
		Version:             2,
		MitreAttackMappings: []string{"T1070.006"}, // Indicator Removal: Timestomp
		SupportedUIFeatures: []string{},
		Author:              "@galoryber",
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_LINUX, agentstructs.SUPPORTED_OS_MACOS, agentstructs.SUPPORTED_OS_WINDOWS},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:          "action",
				CLIName:       "action",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Description:   "Action to perform: get (show timestamps), copy (from another file), set (specific time), match (blend with directory), random (random time in range)",
				Choices:       []string{"get", "copy", "set", "match", "random"},
				DefaultValue:  "get",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: true,
						GroupName:           "Default",
						UIModalPosition:     0,
					},
				},
			},
			{
				Name:          "target",
				CLIName:       "target",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:   "Target file to modify or read timestamps from",
				DefaultValue:  "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: true,
						GroupName:           "Default",
						UIModalPosition:     1,
					},
				},
			},
			{
				Name:          "source",
				CLIName:       "source",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:   "Source file to copy timestamps from (for 'copy' action), or range start date (for 'random' action)",
				DefaultValue:  "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
						UIModalPosition:     2,
					},
				},
			},
			{
				Name:          "timestamp",
				CLIName:       "timestamp",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:   "Timestamp to set (for 'set' action), or range end date (for 'random' action). Formats: 2024-01-15T10:30:00Z, 2024-01-15 10:30:00, 2024-01-15, 01/15/2024",
				DefaultValue:  "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
						UIModalPosition:     3,
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
		TaskFunctionOPSECPre: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTTaskOPSECPreTaskMessageResponse {
			return agentstructs.PTTTaskOPSECPreTaskMessageResponse{
				TaskID:             taskData.Task.ID,
				Success:            true,
				OpsecPreBlocked:    false,
				OpsecPreMessage:    "OPSEC WARNING: Timestomping modifies file MAC times to evade forensic analysis. Alters NTFS $STANDARD_INFORMATION timestamps. Detectable by comparing $SI vs $FILE_NAME timestamps (Sysmon, MFT analysis). Anti-forensics technique — use only when operationally justified.",
				OpsecPreBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionCreateTasking: func(task *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  task.Task.ID,
			}

			action, _ := task.Args.GetStringArg("action")
			target, _ := task.Args.GetStringArg("target")
			source, _ := task.Args.GetStringArg("source")
			timestamp, _ := task.Args.GetStringArg("timestamp")

			displayParams := action + " " + target
			if source != "" {
				displayParams += " (from: " + source + ")"
			}
			if timestamp != "" {
				displayParams += " (time: " + timestamp + ")"
			}
			response.DisplayParams = &displayParams
			if action == "copy" || action == "set" || action == "match" || action == "random" {
				createArtifact(task.Task.ID, "File Modify", "Timestomp "+displayParams)
			}

			return response
		},
	})
}
