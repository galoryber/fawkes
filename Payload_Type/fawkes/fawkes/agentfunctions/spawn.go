package agentfunctions

import (
	"encoding/json"
	"fmt"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
	"github.com/MythicMeta/MythicContainer/logging"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "spawn",
		Description:         "Spawn a suspended process or thread for use with injection techniques like apc-injection.",
		HelpString:          "spawn",
		Version:             1,
		MitreAttackMappings: []string{"T1055"}, // Process Injection
		SupportedUIFeatures: []string{},
		Author:              "@galoryber",
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_WINDOWS},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:             "mode",
				ModalDisplayName: "Spawn Mode",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Description:      "Create a suspended process or a suspended thread in an existing process",
				Choices: []string{
					"process",
					"thread",
				},
				DefaultValue: "process",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: true,
						GroupName:           "Process",
						UIModalPosition:     0,
					},
					{
						ParameterIsRequired: true,
						GroupName:           "Thread",
						UIModalPosition:     0,
					},
				},
			},
			{
				Name:             "path",
				ModalDisplayName: "Executable Path",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Path to executable (e.g., notepad.exe or C:\\Windows\\System32\\notepad.exe)",
				DefaultValue:     "C:\\Windows\\System32\\notepad.exe",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: true,
						GroupName:           "Process",
						UIModalPosition:     1,
					},
				},
			},
			{
				Name:             "pid",
				ModalDisplayName: "Target PID",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				Description:      "Process ID to create suspended thread in",
				DefaultValue:     0,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: true,
						GroupName:           "Thread",
						UIModalPosition:     1,
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

			mode, err := taskData.Args.GetStringArg("mode")
			if err != nil {
				logging.LogError(err, "Failed to get mode")
				response.Success = false
				response.Error = "Failed to get spawn mode: " + err.Error()
				return response
			}

			var displayParams string
			params := make(map[string]interface{})
			params["mode"] = mode

			switch mode {
			case "process":
				path, err := taskData.Args.GetStringArg("path")
				if err != nil {
					logging.LogError(err, "Failed to get path")
					response.Success = false
					response.Error = "Failed to get executable path: " + err.Error()
					return response
				}
				if path == "" {
					response.Success = false
					response.Error = "Executable path cannot be empty"
					return response
				}
				params["path"] = path
				displayParams = fmt.Sprintf("Mode: process\nExecutable: %s", path)

			case "thread":
				pid, err := taskData.Args.GetNumberArg("pid")
				if err != nil {
					logging.LogError(err, "Failed to get pid")
					response.Success = false
					response.Error = "Failed to get PID: " + err.Error()
					return response
				}
				if pid <= 0 {
					response.Success = false
					response.Error = "Invalid PID specified (must be greater than 0)"
					return response
				}
				params["pid"] = int(pid)
				displayParams = fmt.Sprintf("Mode: thread\nTarget PID: %d", int(pid))

			default:
				response.Success = false
				response.Error = fmt.Sprintf("Invalid mode: %s. Use 'process' or 'thread'", mode)
				return response
			}

			response.DisplayParams = &displayParams

			paramsJSON, err := json.Marshal(params)
			if err != nil {
				logging.LogError(err, "Failed to marshal parameters")
				response.Success = false
				response.Error = "Failed to create task parameters: " + err.Error()
				return response
			}

			taskData.Args.SetManualArgs(string(paramsJSON))

			return response
		},
	})
}
