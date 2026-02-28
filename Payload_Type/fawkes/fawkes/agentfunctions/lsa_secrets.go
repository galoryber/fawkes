package agentfunctions

import (
	"fmt"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "lsa-secrets",
		Description:         "Extract LSA secrets (service passwords, DPAPI keys, machine account) and cached domain credentials (DCC2) from the SECURITY hive. Requires SYSTEM privileges.",
		HelpString:          "lsa-secrets -action <dump|cached>",
		Version:             1,
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1003.004", "T1003.005"}, // LSA Secrets, Cached Domain Credentials
		SupportedUIFeatures: []string{},
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_WINDOWS},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:          "action",
				CLIName:       "action",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:       []string{"dump", "cached"},
				DefaultValue:  "dump",
				Description:   "Action: dump (all LSA secrets) or cached (cached domain credentials only, DCC2 format)",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: true,
						UIModalPosition:     1,
						GroupName:            "Default",
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
		TaskFunctionCreateTasking: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  taskData.Task.ID,
			}
			action, _ := taskData.Args.GetStringArg("action")
			display := fmt.Sprintf("LSA secrets %s", action)
			response.DisplayParams = &display
			createArtifact(taskData.Task.ID, "API Call", fmt.Sprintf("LSA secret extraction via registry — %s", action))
			return response
		},
	})
}
