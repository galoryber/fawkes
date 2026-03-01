package agentfunctions

import (
	"fmt"
	"strings"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
	"github.com/MythicMeta/MythicContainer/logging"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "mv",
		Description:         "mv <source> <destination> - Move a file from source to destination",
		HelpString:          "mv <source> <destination>",
		Version:             1,
		MitreAttackMappings: []string{"T1070.004"}, // Indicator Removal: File Deletion
		SupportedUIFeatures: []string{},
		Author:              "@galoryber",
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_LINUX, agentstructs.SUPPORTED_OS_MACOS, agentstructs.SUPPORTED_OS_WINDOWS},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:          "source",
				CLIName:       "source",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:   "Source file path",
				DefaultValue:  "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: true,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:          "destination",
				CLIName:       "destination",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:   "Destination file path",
				DefaultValue:  "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: true,
						GroupName:           "Default",
					},
				},
			},
		},
		TaskFunctionParseArgString: func(args *agentstructs.PTTaskMessageArgsData, input string) error {
			if input == "" {
				return nil
			}
			// Parse space-separated arguments: mv <source> <destination>
			// Try to parse as JSON first
			if err := args.LoadArgsFromJSONString(input); err == nil {
				return nil
			}
			// If not JSON, parse as space-separated string with quote awareness
			// so that mv "C:\Program Files\foo.txt" "C:\Program Files\bar.txt" works
			source, rest := extractQuotedArg(strings.TrimSpace(input))
			destination, _ := extractQuotedArg(strings.TrimSpace(rest))
			if source == "" || destination == "" {
				return fmt.Errorf("mv requires two arguments: source and destination")
			}
			args.AddArg(agentstructs.CommandParameter{
				Name:          "source",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:  source,
			})
			args.AddArg(agentstructs.CommandParameter{
				Name:          "destination",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:  destination,
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
			createArtifact(task.Task.ID, "File Write", "Move "+source+" to "+destination)
			return response
		},
	})
}
