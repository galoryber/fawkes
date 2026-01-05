package agentfunctions

import (
	"fmt"
	"strings"

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
		TaskFunctionParseArgString: func(args *agentstructs.PTTaskMessageArgsData, input string) error {
			// Parse space-separated arguments: cp <source> <destination>
			// Try to parse as JSON first
			if err := args.LoadArgsFromJSONString(input); err == nil {
				return nil
			}
			// If not JSON, parse as space-separated string
			// Split on first space to handle paths with spaces
			parts := strings.SplitN(input, " ", 2)
			if len(parts) != 2 {
				return fmt.Errorf("cp requires two arguments: source and destination")
			}
			args.AddArg(agentstructs.CommandParameter{
				Name:          "source",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:  parts[0],
			})
			args.AddArg(agentstructs.CommandParameter{
				Name:          "destination",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:  parts[1],
			})
			return nil
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
