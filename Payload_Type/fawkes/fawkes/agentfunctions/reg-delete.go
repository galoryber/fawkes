package agentfunctions

import (
	"encoding/json"
	"fmt"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
	"github.com/MythicMeta/MythicContainer/logging"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "reg-delete",
		Description:         "Delete a registry key or value from the Windows Registry. Can delete individual values or entire keys (with optional recursive subkey deletion).",
		HelpString:          "reg-delete -hive HKCU -path \"Software\\TestKey\" [-name \"ValueName\"] [-recursive true]",
		Version:             1,
		MitreAttackMappings: []string{"T1112"},
		SupportedUIFeatures: []string{},
		Author:              "@galoryber",
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_WINDOWS},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:             "hive",
				ModalDisplayName: "Registry Hive",
				CLIName:          "hive",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Description:      "Registry hive",
				DefaultValue:     "HKCU",
				Choices:          []string{"HKLM", "HKCU", "HKCR", "HKU", "HKCC"},
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: true,
						GroupName:           "Default",
						UIModalPosition:     0,
					},
				},
			},
			{
				Name:             "path",
				ModalDisplayName: "Registry Path",
				CLIName:          "path",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Registry key path to delete (or parent key path when deleting a value)",
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: true,
						GroupName:           "Default",
						UIModalPosition:     1,
					},
				},
			},
			{
				Name:             "name",
				ModalDisplayName: "Value Name",
				CLIName:          "name",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Value name to delete (if empty, deletes the key itself)",
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
						UIModalPosition:     2,
					},
				},
			},
			{
				Name:             "recursive",
				ModalDisplayName: "Recursive",
				CLIName:          "recursive",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:          []string{"false", "true"},
				Description:      "Recursively delete all subkeys (only for key deletion, not value deletion)",
				DefaultValue:     "false",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
						UIModalPosition:     3,
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

			hive, err := taskData.Args.GetStringArg("hive")
			if err != nil {
				logging.LogError(err, "Failed to get hive")
				response.Success = false
				response.Error = "Failed to get registry hive: " + err.Error()
				return response
			}

			path, err := taskData.Args.GetStringArg("path")
			if err != nil {
				logging.LogError(err, "Failed to get path")
				response.Success = false
				response.Error = "Failed to get registry path: " + err.Error()
				return response
			}

			name, _ := taskData.Args.GetStringArg("name")
			recursive, _ := taskData.Args.GetStringArg("recursive")

			params := map[string]string{
				"hive":      hive,
				"path":      path,
				"name":      name,
				"recursive": recursive,
			}

			paramsJSON, err := json.Marshal(params)
			if err != nil {
				logging.LogError(err, "Failed to marshal parameters")
				response.Success = false
				response.Error = "Failed to create task parameters: " + err.Error()
				return response
			}

			taskData.Args.SetManualArgs(string(paramsJSON))

			var displayParams string
			if name != "" {
				displayName := name
				if displayName == "" {
					displayName = "(Default)"
				}
				displayParams = fmt.Sprintf("Delete value: %s\\%s\\%s", hive, path, displayName)
			} else {
				displayParams = fmt.Sprintf("Delete key: %s\\%s (recursive=%s)", hive, path, recursive)
			}
			response.DisplayParams = &displayParams
			createArtifact(taskData.Task.ID, "Registry Write", displayParams)

			return response
		},
	})
}
