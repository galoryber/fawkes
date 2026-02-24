package agentfunctions

import (
	"fmt"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
	"github.com/MythicMeta/MythicContainer/mythicrpc"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "klist",
		Description:         "Enumerate cached Kerberos tickets — list TGTs and service tickets, purge cache, export tickets for pass-the-ticket",
		HelpString:          "klist\nklist -action list\nklist -action list -server krbtgt\nklist -action purge\nklist -action dump -server krbtgt/DOMAIN.LOCAL",
		Version:             1,
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1558", "T1550.003"},
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
				Description:      "Action to perform: list (enumerate tickets), purge (clear cache), dump (export ticket data)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:          []string{"list", "purge", "dump"},
				DefaultValue:     "list",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "server",
				CLIName:          "server",
				ModalDisplayName: "Server Filter",
				Description:      "Filter by server name (list) or target SPN for dump (e.g., krbtgt/DOMAIN.LOCAL)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:     "",
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

			action, _ := taskData.Args.GetStringArg("action")
			server, _ := taskData.Args.GetStringArg("server")

			displayMsg := fmt.Sprintf("klist %s", action)
			if server != "" {
				displayMsg += fmt.Sprintf(" (server=%s)", server)
			}
			response.DisplayParams = &displayMsg

			mythicrpc.SendMythicRPCArtifactCreate(mythicrpc.MythicRPCArtifactCreateMessage{
				TaskID:           taskData.Task.ID,
				BaseArtifactType: "API Call",
				ArtifactMessage:  fmt.Sprintf("Kerberos ticket cache %s", action),
			})

			return response
		},
	})
}
