package agentfunctions

import (
	"fmt"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
	"github.com/MythicMeta/MythicContainer/logging"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "kill",
		Description:         "Terminate a process by PID.",
		HelpString:          "kill -pid 1234",
		Version:             1,
		MitreAttackMappings: []string{"T1489"}, // Service Stop (closest mapping)
		SupportedUIFeatures: []string{},
		Author:              "@galoryber",
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_WINDOWS, agentstructs.SUPPORTED_OS_LINUX, agentstructs.SUPPORTED_OS_MACOS},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:             "pid",
				ModalDisplayName: "Process ID",
				CLIName:          "pid",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				Description:      "PID of the process to terminate",
				DefaultValue:     0,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: true,
						GroupName:           "Default",
						UIModalPosition:     0,
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
		TaskFunctionCreateTasking: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  taskData.Task.ID,
			}

			pid, err := taskData.Args.GetNumberArg("pid")
			if err != nil {
				logging.LogError(err, "Failed to get pid")
				response.Success = false
				response.Error = "Failed to get PID: " + err.Error()
				return response
			}

			if pid <= 0 {
				response.Success = false
				response.Error = "PID must be greater than 0"
				return response
			}

			displayParams := fmt.Sprintf("PID: %d", int(pid))
			response.DisplayParams = &displayParams

			return response
		},
	})
}
