package agentfunctions

import (
	"fmt"
	"strings"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "proc-info",
		Description:         "Deep process inspection via /proc filesystem: cmdline, environment, capabilities, cgroups, fds, namespaces (T1057)",
		HelpString:          "proc-info -action <info|connections|mounts|modules> [-pid <PID>]",
		Version:             1,
		SupportedUIFeatures: []string{},
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1057", "T1082", "T1049"},
		ScriptOnlyCommand:   false,
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_LINUX},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:             "action",
				ModalDisplayName: "Action",
				CLIName:          "action",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:          []string{"info", "connections", "mounts", "modules"},
				Description:      "Action: info (detailed process inspection), connections (network connections with PIDs), mounts (filesystem mounts), modules (loaded kernel modules)",
				DefaultValue:     "info",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "pid",
				ModalDisplayName: "PID",
				CLIName:          "pid",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Target process ID (default: current process). Only used with 'info' action.",
				DynamicQueryFunction: getProcessList,
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
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
		TaskFunctionOPSECPre: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTTaskOPSECPreTaskMessageResponse {
			action, _ := taskData.Args.GetStringArg("action")
			msg := fmt.Sprintf("OPSEC WARNING: Process information gathering (%s). ", action)
			switch action {
			case "modules", "memory":
				msg += "Enumerating process modules/memory regions uses OpenProcess + NtQueryVirtualMemory. Accessing other processes may trigger cross-process access alerts."
			case "handles":
				msg += "Handle enumeration uses NtQuerySystemInformation — queries system-wide handle table."
			default:
				msg += "Process detail enumeration. Low risk for own-process queries, higher risk for cross-process."
			}
			return agentstructs.PTTTaskOPSECPreTaskMessageResponse{
				TaskID:             taskData.Task.ID,
				Success:            true,
				OpsecPreBlocked:    false,
				OpsecPreMessage:    msg,
				OpsecPreBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionProcessResponse: func(processResponse agentstructs.PtTaskProcessResponseMessage) agentstructs.PTTaskProcessResponseMessageResponse {
			response := agentstructs.PTTaskProcessResponseMessageResponse{
				TaskID:  processResponse.TaskData.Task.ID,
				Success: true,
			}
			action, _ := processResponse.TaskData.Args.GetStringArg("action")
			responseText, ok := processResponse.Response.(string)
			if !ok || responseText == "" {
				return response
			}
			pid, _ := processResponse.TaskData.Args.GetStringArg("pid")
			switch action {
			case "info":
				msg := "proc-info inspection"
				if pid != "" && pid != "0" {
					msg = fmt.Sprintf("proc-info PID %s inspected", pid)
				}
				createArtifact(processResponse.TaskData.Task.ID, "Process Discovery", msg)
			case "connections":
				count := strings.Count(responseText, "\n")
				createArtifact(processResponse.TaskData.Task.ID, "Network Discovery",
					fmt.Sprintf("proc-info connections: %d entries enumerated", count))
			case "mounts":
				createArtifact(processResponse.TaskData.Task.ID, "System Discovery",
					"proc-info mounts enumerated")
			case "modules":
				createArtifact(processResponse.TaskData.Task.ID, "System Discovery",
					"proc-info kernel modules enumerated")
			}
			return response
		},
		TaskFunctionCreateTasking: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  taskData.Task.ID,
			}
			action, _ := taskData.Args.GetStringArg("action")
			display := action
			pid, _ := parsePIDFromArg(taskData)
			if pid > 0 {
				display += fmt.Sprintf(" (PID %d)", pid)
			}
			response.DisplayParams = &display
			return response
		},
	})
}
