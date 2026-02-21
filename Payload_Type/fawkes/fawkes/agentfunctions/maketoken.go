package agentfunctions

import (
	"fmt"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "make-token",
		Description:         "Create a token from credentials (domain\\username password) and impersonate it",
		HelpString:          "make-token -username <username> -domain <domain> -password <password>",
		Version:             1,
		SupportedUIFeatures: []string{},
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1134.001"},
		ScriptOnlyCommand:   false,
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:             "username",
				ModalDisplayName: "Username",
				CLIName:          "username",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Username to create token for",
				Choices:          []string{},
				DefaultValue:     "",
				SupportedAgents:  []string{},
				ChoicesAreAllCommands:         false,
				ChoicesAreLoadedCommands:      false,
				FilterCommandChoicesByCommandAttributes: map[string]string{},
				DynamicQueryFunction:                    nil,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: true,
						UIModalPosition:     1,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "domain",
				ModalDisplayName: "Domain",
				CLIName:          "domain",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Domain for the user (use '.' for local)",
				Choices:          []string{},
				DefaultValue:     ".",
				SupportedAgents:  []string{},
				ChoicesAreAllCommands:         false,
				ChoicesAreLoadedCommands:      false,
				FilterCommandChoicesByCommandAttributes: map[string]string{},
				DynamicQueryFunction:                    nil,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     2,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "password",
				ModalDisplayName: "Password",
				CLIName:          "password",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Password for the user",
				Choices:          []string{},
				DefaultValue:     "",
				SupportedAgents:  []string{},
				ChoicesAreAllCommands:         false,
				ChoicesAreLoadedCommands:      false,
				FilterCommandChoicesByCommandAttributes: map[string]string{},
				DynamicQueryFunction:                    nil,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: true,
						UIModalPosition:     3,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "logon_type",
				ModalDisplayName: "Logon Type",
				CLIName:          "logon_type",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				Description:      "Type of logon operation: 2=Interactive, 3=Network, 4=Batch, 5=Service, 7=Unlock, 9=NewCredentials (default)",
				Choices:          []string{},
				DefaultValue:     9,
				SupportedAgents:  []string{},
				ChoicesAreAllCommands:         false,
				ChoicesAreLoadedCommands:      false,
				FilterCommandChoicesByCommandAttributes: map[string]string{},
				DynamicQueryFunction:                    nil,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     4,
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
			username, _ := taskData.Args.GetStringArg("username")
			domain, _ := taskData.Args.GetStringArg("domain")
			createArtifact(taskData.Task.ID, "Logon", fmt.Sprintf("LogonUserW %s\\%s (type 9)", domain, username))
			return response
		},
		TaskFunctionProcessResponse: nil,
	})
}

