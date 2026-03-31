package agentfunctions

import (
	"encoding/json"
	"fmt"
	"strings"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
	"github.com/mitchellh/mapstructure"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "cat",
		Description:         "Display file contents with optional line range, numbering, and size protection",
		HelpString:          "cat [path] — read file | cat -path file -start 10 -end 20 — line range | cat -path file -number true — with line numbers",
		Version:             3,
		MitreAttackMappings: []string{"T1005"}, // Data from Local System
		SupportedUIFeatures: []string{},
		Author:              "@galoryber",
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS:        []string{agentstructs.SUPPORTED_OS_LINUX, agentstructs.SUPPORTED_OS_MACOS, agentstructs.SUPPORTED_OS_WINDOWS},
			CommandIsSuggested: true,
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:             "path",
				CLIName:          "path",
				ModalDisplayName: "File Path",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Path to the file to read",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: true,
						UIModalPosition:     1,
					},
				},
			},
			{
				Name:             "start",
				CLIName:          "start",
				ModalDisplayName: "Start Line",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				Description:      "Starting line number (1-based, default: beginning of file)",
				DefaultValue:     0,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     2,
					},
				},
			},
			{
				Name:             "end",
				CLIName:          "end",
				ModalDisplayName: "End Line",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				Description:      "Ending line number (default: end of file)",
				DefaultValue:     0,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     3,
					},
				},
			},
			{
				Name:             "number",
				CLIName:          "number",
				ModalDisplayName: "Line Numbers",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_BOOLEAN,
				Description:      "Show line numbers",
				DefaultValue:     false,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     4,
					},
				},
			},
			{
				Name:             "max",
				CLIName:          "max",
				ModalDisplayName: "Max Size (KB)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				Description:      "Maximum output size in KB (default: 5120 = 5MB)",
				DefaultValue:     0,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     5,
					},
				},
			},
		},
		TaskFunctionParseArgString: func(args *agentstructs.PTTaskMessageArgsData, input string) error {
			input = strings.TrimSpace(input)
			// Try JSON first — supports {"path": "..."} and {"full_path": "..."} from file browser
			var jsonArgs map[string]interface{}
			if err := json.Unmarshal([]byte(input), &jsonArgs); err == nil {
				// File browser format
				if fullPath, ok := jsonArgs["full_path"].(string); ok && fullPath != "" {
					args.AddArg(agentstructs.CommandParameter{
						Name:          "path",
						ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
						DefaultValue:  fullPath,
					})
					return nil
				}
				// Standard JSON parameters
				if err := args.LoadArgsFromJSONString(input); err == nil {
					return nil
				}
			}
			// Plain text — treat as file path
			args.SetManualArgs(input)
			return nil
		},
		TaskFunctionParseArgDictionary: func(args *agentstructs.PTTaskMessageArgsData, input map[string]interface{}) error {
			// Check if this is from the file browser (has full_path field)
			fileBrowserData := agentstructs.FileBrowserTask{}
			if err := mapstructure.Decode(input, &fileBrowserData); err == nil && fileBrowserData.FullPath != "" {
				args.AddArg(agentstructs.CommandParameter{
					Name:          "path",
					ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
					DefaultValue:  fileBrowserData.FullPath,
				})
				return nil
			}
			return args.LoadArgsFromDictionary(input)
		},
		TaskFunctionCreateTasking: func(task *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  task.Task.ID,
			}
			path, _ := task.Args.GetStringArg("path")
			start, _ := task.Args.GetNumberArg("start")
			end, _ := task.Args.GetNumberArg("end")
			number, _ := task.Args.GetBooleanArg("number")

			display := path
			if start > 0 || end > 0 {
				if end > 0 {
					display = fmt.Sprintf("%s [lines %d-%d]", path, int(start), int(end))
				} else {
					display = fmt.Sprintf("%s [from line %d]", path, int(start))
				}
			}
			if number {
				display += " (numbered)"
			}
			response.DisplayParams = &display
			return response
		},
	})
}
