package agentfunctions

import (
	"encoding/json"
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
			// Check if this is from the file browser (has full_path field)
			fileBrowserData := agentstructs.FileBrowserTask{}
			if err := mapstructure.Decode(input, &fileBrowserData); err == nil && fileBrowserData.FullPath != "" {
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
			// Otherwise parse as simple path dictionary (e.g., {"path": "C:\\Users"})
			if path, ok := input["path"].(string); ok {
				args.AddArg(agentstructs.CommandParameter{
					Name:          "path",
					ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
					DefaultValue:  path,
				})
			} else {
				logging.LogError(nil, "Failed to get path from dictionary input")
			}
			args.AddArg(agentstructs.CommandParameter{
				Name:          "file_browser",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_BOOLEAN,
				DefaultValue:  false,
			})
			return nil
		},
		TaskFunctionParseArgString: func(args *agentstructs.PTTaskMessageArgsData, input string) error {
			input = strings.TrimSpace(input)
			// Try JSON first (e.g., {"path": "C:\\Users"} or {"full_path": "..."} from API)
			var jsonArgs map[string]interface{}
			if err := json.Unmarshal([]byte(input), &jsonArgs); err == nil {
				// Check for file browser format (full_path)
				if fullPath, ok := jsonArgs["full_path"].(string); ok && fullPath != "" {
					args.AddArg(agentstructs.CommandParameter{
						Name:          "path",
						ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
						DefaultValue:  fullPath,
					})
					args.AddArg(agentstructs.CommandParameter{
						Name:          "file_browser",
						ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_BOOLEAN,
						DefaultValue:  true,
					})
					return nil
				}
				// Check for explicit file_browser flag
				fileBrowser, _ := jsonArgs["file_browser"].(bool)
				if path, ok := jsonArgs["path"].(string); ok {
					args.AddArg(agentstructs.CommandParameter{
						Name:          "path",
						ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
						DefaultValue:  path,
					})
					args.AddArg(agentstructs.CommandParameter{
						Name:          "file_browser",
						ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_BOOLEAN,
						DefaultValue:  fileBrowser,
					})
					return nil
				}
			}
			// Strip surrounding quotes
			if len(input) >= 2 {
				if (input[0] == '"' && input[len(input)-1] == '"') ||
					(input[0] == '\'' && input[len(input)-1] == '\'') {
					input = input[1 : len(input)-1]
				}
			}
			if input == "" {
				input = "."
			}
			args.AddArg(agentstructs.CommandParameter{
				Name:          "path",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:  input,
			})
			args.AddArg(agentstructs.CommandParameter{
				Name:          "file_browser",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_BOOLEAN,
				DefaultValue:  false,
			})
			return nil
		},
	})
}
