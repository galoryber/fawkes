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
		Description:         "Spawn a suspended process or thread for use with injection techniques like apc-injection. Supports PPID spoofing and non-Microsoft DLL blocking.",
		HelpString:          "spawn -path <executable> [-ppid <parent_pid>] [-blockdlls true]",
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
				Description:      "Path to executable for process spawn (e.g., notepad.exe). Leave empty and set pid for thread mode.",
				DefaultValue:     "C:\\Windows\\System32\\notepad.exe",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
						UIModalPosition:     0,
					},
				},
			},
			{
				Name:             "pid",
				ModalDisplayName: "Target PID (Thread Mode)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				Description:      "Process ID to create suspended thread in. If set (>0), thread mode is used instead of process mode.",
				DefaultValue:     0,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
						UIModalPosition:     1,
					},
				},
			},
			{
				Name:             "ppid",
				ModalDisplayName: "Parent PID (PPID Spoofing)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				Description:      "Spoof parent process ID (0 = don't spoof). The spawned process will appear as a child of this PID. Process mode only.",
				DefaultValue:     0,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
						UIModalPosition:     2,
					},
				},
			},
			{
				Name:             "blockdlls",
				ModalDisplayName: "Block Non-MS DLLs",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_BOOLEAN,
				Description:      "Block non-Microsoft-signed DLLs from loading in the spawned process. Prevents most EDR hooking DLLs from injecting. Process mode only.",
				DefaultValue:     false,
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
			// Try JSON first, fall back to LoadArgsFromJSONString
			var raw map[string]interface{}
			if err := json.Unmarshal([]byte(input), &raw); err != nil {
				return args.LoadArgsFromJSONString(input)
			}
			// Filter to known params only (exclude agent-internal keys like "mode")
			clean := make(map[string]interface{})
			for _, key := range []string{"path", "pid", "ppid", "blockdlls"} {
				if v, ok := raw[key]; ok {
					clean[key] = v
				}
			}
			return args.LoadArgsFromDictionary(clean)
		},
		TaskFunctionParseArgDictionary: func(args *agentstructs.PTTaskMessageArgsData, input map[string]interface{}) error {
			return args.LoadArgsFromDictionary(input)
		},
		TaskFunctionCreateTasking: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  taskData.Task.ID,
			}

			var displayParams string
			params := make(map[string]interface{})

			// Determine mode: if pid > 0, use thread mode; otherwise process mode
			pid, _ := taskData.Args.GetNumberArg("pid")
			if pid > 0 {
				// Thread mode
				params["mode"] = "thread"
				params["pid"] = int(pid)
				displayParams = fmt.Sprintf("Suspended thread in PID: %d", int(pid))
			} else {
				// Process mode
				params["mode"] = "process"
				path, err := taskData.Args.GetStringArg("path")
				if err != nil {
					logging.LogError(err, "Failed to get path")
					response.Success = false
					response.Error = "Failed to get executable path: " + err.Error()
					return response
				}
				if path == "" {
					path = "C:\\Windows\\System32\\notepad.exe"
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
