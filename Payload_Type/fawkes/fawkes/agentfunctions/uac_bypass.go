package agentfunctions

import (
	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "uac-bypass",
		Description:         "Bypass User Account Control (UAC) to escalate from medium to high integrity. Registry-based hijack techniques that trigger auto-elevating Windows binaries.",
		HelpString:          "uac-bypass [-technique fodhelper] [-command C:\\path\\to\\payload.exe]",
		Version:             1,
		SupportedUIFeatures: []string{},
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1548.002"},
		ScriptOnlyCommand:   false,
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_WINDOWS},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:             "technique",
				ModalDisplayName: "Bypass Technique",
				CLIName:          "technique",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:          []string{"fodhelper", "computerdefaults", "sdclt"},
				Description:      "UAC bypass technique: fodhelper (Win10+, ms-settings hijack), computerdefaults (Win10+, ms-settings hijack), sdclt (Win10, Folder handler hijack)",
				DefaultValue:     "fodhelper",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "command",
				ModalDisplayName: "Command to Execute",
				CLIName:          "command",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Command/path to execute with elevated privileges. Default: spawn new elevated callback (agent's own exe).",
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
		},
		AssociatedBrowserScript: nil,
		TaskFunctionOPSECPre:    nil,
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
			technique, _ := taskData.Args.GetStringArg("technique")
			if technique == "" {
				technique = "fodhelper"
			}
			createArtifact(taskData.Task.ID, "Registry Write", "HKCU\\Software\\Classes\\ms-settings\\Shell\\Open\\command (UAC bypass via "+technique+")")
			createArtifact(taskData.Task.ID, "Process Create", "Auto-elevation trigger: "+technique+".exe")
			return response
		},
		TaskFunctionProcessResponse: nil,
	})
}
