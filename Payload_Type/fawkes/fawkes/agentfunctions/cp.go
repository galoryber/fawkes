package agentfunctions

import (
	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
	"github.com/MythicMeta/MythicContainer/logging"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "cp",
		Description:         "cp <source> <destination> - Copy a file from source to destination",
		HelpString:          "cp <source> <destination>",
		Version:             1,
		MitreAttackMappings: []string{"T1105"}, // Ingress Tool Transfer
		SupportedUIFeatures: []string{},
		Author:              "@galoryber",
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_LINUX, agentstructs.SUPPORTED_OS_MACOS, agentstructs.SUPPORTED_OS_WINDOWS},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:          "source",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:   "Source file path",
				Required:      true,
			},
			{
				Name:          "destination",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:   "Destination file path",
				Required:      true,
			},
		},
		TaskFunctionParseArgString: func(args *agentstructs.PTTaskMessageArgsData, input string) error {
			return args.LoadArgsFromJSONString(input)
		},
		TaskFunctionParseArgDictionary: func(args *agentstructs.PTTaskMessageArgsData, input map[string]interface{}) error {
			return args.LoadArgsFromDictionary(input)
		},
		TaskFunctionCreateTasking: func(task *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  task.Task.ID,
			}

			source, err1 := task.Args.GetStringArg("source")
			destination, err2 := task.Args.GetStringArg("destination")

			if err1 != nil || err2 != nil {
				logging.LogError(err1, "Failed to get source or destination arguments")
				response.Error = "Failed to get required arguments"
				response.Success = false
				return response
			}

			displayParams := source + " -> " + destination
			response.DisplayParams = &displayParams
			return response
		},
	})
}
