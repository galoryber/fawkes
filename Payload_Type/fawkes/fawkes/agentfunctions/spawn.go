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
		Description:         "Spawn a suspended process or thread for use with injection techniques like apc-injection. Supports PPID spoofing and non-Microsoft DLL blocking.",
		HelpString:          "spawn",
		Version:             2,
		MitreAttackMappings: []string{"T1055", "T1134.004"}, // Process Injection, Parent PID Spoofing
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
				Name:             "ppid",
				ModalDisplayName: "Parent PID",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				Description:      "Spoof parent process ID (0 = don't spoof). The spawned process will appear as a child of this PID in Task Manager and EDR telemetry.",
				DefaultValue:     0,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Process",
						UIModalPosition:     1,
					},
				},
			},
			{
				Name:             "blockdlls",
				ModalDisplayName: "Block Non-MS DLLs",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_BOOLEAN,
				Description:      "Block non-Microsoft-signed DLLs from loading in the spawned process. Prevents most EDR hooking DLLs from injecting.",
				DefaultValue:     false,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Process",
						UIModalPosition:     2,
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

				// Optional PPID spoofing
				if ppid, err := taskData.Args.GetNumberArg("ppid"); err == nil && ppid > 0 {
					params["ppid"] = int(ppid)
					displayParams += fmt.Sprintf(", PPID spoof: %d", int(ppid))
				}

				// Optional DLL blocking
				if blockdlls, err := taskData.Args.GetBooleanArg("blockdlls"); err == nil && blockdlls {
					params["blockdlls"] = true
					displayParams += ", blockdlls: on"
				}

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
