package agentfunctions

import (
	"encoding/json"
	"fmt"
	"path/filepath"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "handles",
		Description:         "handles -pid <pid> [-type File] [-show_names] [-max_count 500] - Enumerate open handles/file descriptors in a target process. Windows: NtQuerySystemInformation. Linux: /proc/<pid>/fd. macOS: lsof.",
		HelpString:          "handles -pid <pid> [-type File] [-show_names] [-max_count 500]\n\nWindows: Enumerates NT handles (File, Key, Section, Mutant, etc.) via NtQuerySystemInformation.\nLinux: Reads /proc/<pid>/fd symlinks to enumerate open file descriptors (files, sockets, pipes).\nmacOS: Uses lsof to enumerate open file descriptors.\n\nTypes vary by platform:\n  Windows: File, Key, Section, Mutant, Event, Process, Thread, etc.\n  Linux: file, socket, pipe, device, tty, eventfd, eventpoll, etc.\n  macOS: file, socket, pipe, device, directory, kqueue, etc.",
		Version:             2,
		MitreAttackMappings: []string{"T1057", "T1082"}, // Process Discovery + System Information Discovery
		SupportedUIFeatures: []string{"process_browser:list"},
		Author:              "@galoryber",
		AssociatedBrowserScript: &agentstructs.BrowserScript{
			ScriptPath: filepath.Join(".", "fawkes", "browserscripts", "handles_new.js"),
			Author:     "@galoryber",
		},
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_WINDOWS, agentstructs.SUPPORTED_OS_LINUX, agentstructs.SUPPORTED_OS_MACOS},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:          "pid",
				CLIName:       "pid",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				Description:   "Target process ID to enumerate handles for",
				DefaultValue:  0,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: true,
						UIModalPosition:     1,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:          "type",
				CLIName:       "type",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:   "Filter by handle type (e.g. File, Key, Section, Mutant, Event, Process, Thread)",
				DefaultValue:  "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     2,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:          "show_names",
				CLIName:       "show_names",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_BOOLEAN,
				Description:   "Resolve handle names (slower but more detailed)",
				DefaultValue:  false,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     3,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:          "max_count",
				CLIName:       "max_count",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				Description:   "Maximum handles to enumerate (default: 500)",
				DefaultValue:  500,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     4,
						GroupName:           "Default",
					},
				},
			},
		},
		TaskFunctionParseArgString: func(args *agentstructs.PTTaskMessageArgsData, input string) error {
			if input != "" {
				return args.LoadArgsFromJSONString(input)
			}
			return nil
		},
		TaskFunctionParseArgDictionary: func(args *agentstructs.PTTaskMessageArgsData, input map[string]interface{}) error {
			return args.LoadArgsFromDictionary(input)
		},
		TaskFunctionOPSECPre: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTTaskOPSECPreTaskMessageResponse {
			return agentstructs.PTTTaskOPSECPreTaskMessageResponse{
				TaskID: taskData.Task.ID, Success: true,
				OpsecPreBlocked: false,
				OpsecPreMessage:    "OPSEC WARNING: Enumerating open handles/file descriptors (T1057, T1082). Handle enumeration targets process tokens and access rights, a technique used for privilege escalation. NtQuerySystemInformation calls may be monitored by EDR.",
				OpsecPreBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionProcessResponse: func(processResponse agentstructs.PtTaskProcessResponseMessage) agentstructs.PTTaskProcessResponseMessageResponse {
			response := agentstructs.PTTaskProcessResponseMessageResponse{
				TaskID:  processResponse.TaskData.Task.ID,
				Success: true,
			}
			responseText, ok := processResponse.Response.(string)
			if !ok || responseText == "" || responseText == "[]" {
				return response
			}
			type handleEntry struct {
				Handle   int    `json:"handle"`
				TypeName string `json:"type_name"`
				Name     string `json:"name"`
			}
			type handlesResponse struct {
				PID     int           `json:"pid"`
				Handles []handleEntry `json:"handles"`
			}
			var hr handlesResponse
			if err := json.Unmarshal([]byte(responseText), &hr); err != nil {
				return response
			}
			count := 0
			for _, h := range hr.Handles {
				if h.Name == "" {
					continue
				}
				createArtifact(processResponse.TaskData.Task.ID, "Discovery",
					fmt.Sprintf("Handle: %s — %s (PID %d)", h.TypeName, h.Name, hr.PID))
				count++
				if count >= 50 {
					break
				}
			}
			return response
		},
		TaskFunctionCreateTasking: func(task *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  task.Task.ID,
			}
			os := task.Payload.OS
			if os == "Windows" {
				createArtifact(task.Task.ID, "API Call", "NtQuerySystemInformation(SystemHandleInformation) + NtQueryObject")
			} else if os == "macOS" {
				createArtifact(task.Task.ID, "Process Create", "lsof -p <pid> -F ftn")
			} else {
				createArtifact(task.Task.ID, "FileOpen", "/proc/<pid>/fd")
			}
			if displayParams, err := task.Args.GetFinalArgs(); err == nil && displayParams != "" {
				response.DisplayParams = &displayParams
			}
			return response
		},
	})
}
