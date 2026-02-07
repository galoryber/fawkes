package agentfunctions

import (
	"path/filepath"
	"strings"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
	"github.com/MythicMeta/MythicContainer/logging"
	"github.com/mitchellh/mapstructure"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "ls",
		Description:         "ls [path]",
		Version:             1,
		MitreAttackMappings: []string{"T1083"},
		SupportedUIFeatures: []string{"file_browser:list"},
		Author:              "@xorrior",
		AssociatedBrowserScript: &agentstructs.BrowserScript{
			ScriptPath: filepath.Join(".", "fawkes", "browserscripts", "ls_new.js"),
			Author:     "@its_a_feature_",
		},
		TaskFunctionCreateTasking: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  taskData.Task.ID,
			}
			if path, err := taskData.Args.GetStringArg("path"); err != nil {
				logging.LogError(err, "Failed to get string arg for path")
				response.Error = err.Error()
				response.Success = false
				return response
			} else {
				response.DisplayParams = &path
			}
			return response
		},
		TaskFunctionParseArgDictionary: func(args *agentstructs.PTTaskMessageArgsData, input map[string]interface{}) error {
			// if we get a dictionary, it'll be from the file browser which will supply agentstructs.FileBrowserTask data
			fileBrowserData := agentstructs.FileBrowserTask{}
			//logging.LogDebug("Called TaskFunctionParseArgDictionary in ls")
			if err := mapstructure.Decode(input, &fileBrowserData); err != nil {
				logging.LogError(err, "Failed to get file browser data struct information from dictionary input")
				return err
			} else {
				args.AddArg(agentstructs.CommandParameter{
					Name:          "file_browser",
					ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_BOOLEAN,
					DefaultValue:  true,
				})
				args.AddArg(agentstructs.CommandParameter{
					Name:          "path",
					ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
					DefaultValue:  fileBrowserData.FullPath,
				})
				return nil
			}
		},
		TaskFunctionParseArgString: func(args *agentstructs.PTTaskMessageArgsData, input string) error {
			// Strip whitespace and surrounding quotes so paths like
			// "C:\Program Data" resolve to C:\Program Data
			input = strings.TrimSpace(input)
			if len(input) >= 2 {
				if (input[0] == '"' && input[len(input)-1] == '"') ||
					(input[0] == '\'' && input[len(input)-1] == '\'') {
					input = input[1 : len(input)-1]
				}
			}

			if input == "" {
				args.AddArg(agentstructs.CommandParameter{
					Name:          "path",
					ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
					DefaultValue:  ".",
				})
			} else {
				args.AddArg(agentstructs.CommandParameter{
					Name:          "path",
					ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
					DefaultValue:  input,
				})
			}
			args.AddArg(agentstructs.CommandParameter{
				Name:          "file_browser",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_BOOLEAN,
				DefaultValue:  false,
			})
			return nil
		},
	})
}
