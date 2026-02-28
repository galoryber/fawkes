package agentfunctions

import (
	"fmt"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "wdigest",
		Description:         "Manage WDigest plaintext credential caching in LSASS. Enable to capture cleartext passwords at next interactive logon (Windows 10+ disables WDigest by default).",
		HelpString:          "wdigest -action <status|enable|disable>",
		Version:             1,
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1003.001", "T1112"}, // LSASS Memory + Modify Registry
		SupportedUIFeatures: []string{},
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_WINDOWS},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:          "action",
				CLIName:       "action",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:       []string{"status", "enable", "disable"},
				DefaultValue:  "status",
				Description:   "Action: status (check current state), enable (cache plaintext creds), disable (stop caching)",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: true,
						UIModalPosition:     1,
						GroupName:           "Default",
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
			display := action
			response.DisplayParams = &display
			if action == "enable" || action == "disable" {
				createArtifact(taskData.Task.ID, "Registry Write", fmt.Sprintf("WDigest UseLogonCredential registry modification — %s", action))
			}
			return response
		},
	})
}
