package agentfunctions

import (
	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "getsystem",
		Description:         "Elevate to SYSTEM via named pipe impersonation (requires SeImpersonate privilege and admin)",
		HelpString:          "getsystem [-technique service]",
		Version:             1,
		SupportedUIFeatures: []string{},
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1134.001"},
		ScriptOnlyCommand:   false,
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_WINDOWS},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:             "technique",
				ModalDisplayName: "Technique",
				CLIName:          "technique",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:          []string{"service"},
				Description:      "Escalation technique: service (named pipe + SCM service trigger)",
				DefaultValue:     "service",
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
				technique = "service"
			}
			createArtifact(taskData.Task.ID, "Token Steal", "Named pipe impersonation: CreateNamedPipe + ImpersonateNamedPipeClient ("+technique+" trigger)")
			createArtifact(taskData.Task.ID, "Process Create", "Service creation trigger: cmd.exe /c echo > \\\\.\\pipe\\<random>")
			return response
		},
		TaskFunctionProcessResponse: nil,
	})
}
