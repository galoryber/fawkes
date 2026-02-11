package agentfunctions

import (
	"encoding/json"
	"fmt"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
	"github.com/MythicMeta/MythicContainer/logging"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "reg-read",
		Description:         "Read a value from the Windows Registry. Supports HKLM, HKCU, HKCR, HKU, HKCC hives and all standard value types (REG_SZ, REG_DWORD, REG_BINARY, REG_EXPAND_SZ, REG_MULTI_SZ, REG_QWORD).",
		HelpString:          "reg-read -hive HKLM -path \"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\" -name \"ProgramFilesDir\"",
		Version:             1,
		MitreAttackMappings: []string{"T1012"}, // Query Registry
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
				Description:      "Registry hive to read from",
				DefaultValue:     "HKLM",
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
				Description:      "Registry key path (e.g., SOFTWARE\\Microsoft\\Windows\\CurrentVersion)",
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
				Description:      "Value name to read. Leave empty to enumerate all values under the key.",
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
						UIModalPosition:     2,
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

			params := map[string]string{
				"hive": hive,
				"path": path,
				"name": name,
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
				displayParams = fmt.Sprintf("%s\\%s -> %s", hive, path, name)
			} else {
				displayParams = fmt.Sprintf("%s\\%s (enumerate values)", hive, path)
			}
			response.DisplayParams = &displayParams

			return response
		},
	})
}
