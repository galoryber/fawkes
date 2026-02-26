package agentfunctions

import (
	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
	"github.com/MythicMeta/MythicContainer/mythicrpc"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "syscalls",
		Description:         "Show indirect syscall resolver status. Resolves Nt* syscall numbers from ntdll and generates indirect stubs that jump to ntdll's own syscall;ret gadget, making API calls appear to originate from ntdll.",
		HelpString:          "syscalls [status|list|init]",
		Version:             1,
		MitreAttackMappings: []string{"T1106"},
		SupportedUIFeatures: []string{},
		Author:              "@galoryber",
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_WINDOWS},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:          "action",
				CLIName:       "action",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Description:   "Action to perform",
				DefaultValue:  "status",
				Choices:       []string{"status", "list", "init"},
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
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
		TaskFunctionCreateTasking: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  taskData.Task.ID,
			}

			action, _ := taskData.Args.GetStringArg("action")
			if action == "" {
				action = "status"
			}

			displayStr := "Querying indirect syscall status"
			switch action {
			case "list":
				displayStr = "Listing resolved Nt* syscalls"
			case "init":
				displayStr = "Initializing indirect syscall resolver"

				mythicrpc.SendMythicRPCArtifactCreate(mythicrpc.MythicRPCArtifactCreateMessage{
					TaskID:            taskData.Task.ID,
					BaseArtifactType:  "API Call",
					ArtifactMessage:   "Parse ntdll export table + VirtualAlloc RWX for indirect syscall stubs",
				})
			}
			response.DisplayParams = &displayStr

			return response
		},
	})
}
