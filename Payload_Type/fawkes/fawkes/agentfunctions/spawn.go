package agentfunctions

import (
	"encoding/json"
	"fmt"
	"strings"

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
				Name:             "path",
				ModalDisplayName: "Executable Path",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Path to executable (e.g., notepad.exe or C:\\Windows\\System32\\notepad.exe)",
				DefaultValue:     "C:\\Windows\\System32\\notepad.exe",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: true,
						GroupName:           "Process",
						UIModalPosition:     0,
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
						UIModalPosition:     0,
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

			// Determine mode from the parameter group selection
			groupName := strings.ToLower(taskData.Task.ParameterGroupName)

			var displayParams string
			params := make(map[string]interface{})

			switch groupName {
			case "process":
				params["mode"] = "process"
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
				displayParams = fmt.Sprintf("Executable: %s (suspended)", path)

			case "thread":
				params["mode"] = "thread"
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
				displayParams = fmt.Sprintf("Suspended thread in PID: %d", int(pid))

			default:
				response.Success = false
				response.Error = fmt.Sprintf("Unknown parameter group: %s", taskData.Task.ParameterGroupName)
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
