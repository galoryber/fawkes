package agentfunctions

import (
	"encoding/json"
	"fmt"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
	"github.com/MythicMeta/MythicContainer/logging"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "reg-write",
		Description:         "Write a value to the Windows Registry. Creates keys and values if they don't exist. Supports REG_SZ, REG_EXPAND_SZ, REG_DWORD, REG_QWORD, and REG_BINARY types.",
		HelpString:          "reg-write -hive HKCU -path \"Software\\TestKey\" -name \"TestValue\" -data \"hello\" -type REG_SZ",
		Version:             1,
		MitreAttackMappings: []string{"T1112"}, // Modify Registry
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
				Description:      "Registry hive to write to",
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
				Description:      "Registry key path (will be created if it doesn't exist)",
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
				Description:      "Value name to write (leave empty for default value)",
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
				Name:             "data",
				ModalDisplayName: "Value Data",
				CLIName:          "data",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Data to write. For REG_DWORD/REG_QWORD use decimal number. For REG_BINARY use hex string (e.g., 0102ff).",
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: true,
						GroupName:           "Default",
						UIModalPosition:     3,
					},
				},
			},
			{
				Name:             "reg_type",
				ModalDisplayName: "Value Type",
				CLIName:          "type",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Description:      "Registry value type",
				DefaultValue:     "REG_SZ",
				Choices:          []string{"REG_SZ", "REG_EXPAND_SZ", "REG_DWORD", "REG_QWORD", "REG_BINARY"},
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: true,
						GroupName:           "Default",
						UIModalPosition:     4,
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

			data, err := taskData.Args.GetStringArg("data")
			if err != nil {
				logging.LogError(err, "Failed to get data")
				response.Success = false
				response.Error = "Failed to get value data: " + err.Error()
				return response
			}

			regType, err := taskData.Args.GetStringArg("reg_type")
			if err != nil {
				logging.LogError(err, "Failed to get reg_type")
				response.Success = false
				response.Error = "Failed to get value type: " + err.Error()
				return response
			}

			params := map[string]string{
				"hive":     hive,
				"path":     path,
				"name":     name,
				"data":     data,
				"reg_type": regType,
			}

			paramsJSON, err := json.Marshal(params)
			if err != nil {
				logging.LogError(err, "Failed to marshal parameters")
				response.Success = false
				response.Error = "Failed to create task parameters: " + err.Error()
				return response
			}

			taskData.Args.SetManualArgs(string(paramsJSON))

			displayName := name
			if displayName == "" {
				displayName = "(Default)"
			}
			displayParams := fmt.Sprintf("%s\\%s\\%s = %s [%s]", hive, path, displayName, data, regType)
			response.DisplayParams = &displayParams
			createArtifact(taskData.Task.ID, "Registry Write", displayParams)

			return response
		},
	})
}
