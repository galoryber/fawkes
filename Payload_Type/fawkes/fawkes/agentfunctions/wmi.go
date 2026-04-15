package agentfunctions

import (
	"fmt"
	"path/filepath"
	"regexp"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "wmi",
		Description:         "Execute WMI queries and process creation via COM API (T1047)",
		HelpString:          "wmi -action <execute|query|process-list|os-info> [-target <host>] [-command <cmd>] [-query <wmic_query>]",
		Version:             1,
		SupportedUIFeatures: []string{},
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1047"},
		ScriptOnlyCommand:   false,
		AssociatedBrowserScript: &agentstructs.BrowserScript{ScriptPath: filepath.Join(".", "fawkes", "browserscripts", "wmi_new.js"), Author: "@galoryber"},
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS:                []string{agentstructs.SUPPORTED_OS_WINDOWS},
			CommandCanOnlyBeLoadedLater: true,
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:             "action",
				ModalDisplayName: "Action",
				CLIName:          "action",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:          []string{"execute", "query", "process-list", "os-info"},
				Description:      "execute: create a process, query: run wmic query, process-list: list processes, os-info: OS details",
				DefaultValue:     "os-info",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: true,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:                 "target",
				ModalDisplayName:     "Target Host",
				CLIName:              "target",
				ParameterType:        agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:          "Remote hostname or IP (leave empty for local)",
				DefaultValue:         "",
				DynamicQueryFunction: getActiveHostList,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "command",
				ModalDisplayName: "Command",
				CLIName:          "command",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Command line to execute (for execute action, e.g., 'notepad.exe')",
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "query",
				ModalDisplayName: "WMIC Query",
				CLIName:          "query",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Raw wmic arguments (for query action, e.g., 'os get caption,version')",
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "timeout",
				CLIName:          "timeout",
				ModalDisplayName: "Timeout (seconds)",
				Description:      "Operation timeout in seconds (default: 120). Prevents agent hangs on unreachable targets.",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				DefaultValue:     120,
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
			host, _ := taskData.Args.GetStringArg("host")
			msg := fmt.Sprintf("OPSEC WARNING: WMI %s", action)
			if host != "" && host != "." && host != "localhost" {
				msg = fmt.Sprintf("OPSEC WARNING: Remote WMI %s on %s. Generates WMI activity events (Event ID 5857-5861) and network traffic on TCP 135/dynamic RPC. Remote WMI execution is a common lateral movement indicator.", action, host)
			} else {
				msg = fmt.Sprintf("OPSEC WARNING: Local WMI %s. Generates WMI activity events (Event ID 5857-5861). WMI is commonly monitored for persistence and execution.", action)
			}
			return agentstructs.PTTTaskOPSECPreTaskMessageResponse{
				TaskID:             taskData.Task.ID,
				Success:            true,
				OpsecPreBlocked:    false,
				OpsecPreMessage:    msg,
				OpsecPreBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionOPSECPost: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskOPSECPostTaskMessageResponse {
			return agentstructs.PTTaskOPSECPostTaskMessageResponse{
				TaskID:              taskData.Task.ID,
				Success:             true,
				OpsecPostBlocked:    false,
				OpsecPostMessage:    "OPSEC AUDIT: WMI operation completed. Remote WMI generates Event ID 4624 (logon type 3) on the target. WMI activity is logged in Microsoft-Windows-WMI-Activity/Operational. Process creation via WMI generates Event ID 4688 with creator process wmiprvse.exe.",
				OpsecPostBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionProcessResponse: func(processResponse agentstructs.PtTaskProcessResponseMessage) agentstructs.PTTaskProcessResponseMessageResponse {
			response := agentstructs.PTTaskProcessResponseMessageResponse{
				TaskID:  processResponse.TaskData.Task.ID,
				Success: true,
			}
			responseText, ok := processResponse.Response.(string)
			if !ok || responseText == "" {
				return response
			}
			// Parse: WMI Process Create on <host>:
			re := regexp.MustCompile(`WMI Process Create on (\S+?):`)
			if m := re.FindStringSubmatch(responseText); len(m) > 1 {
				createArtifact(processResponse.TaskData.Task.ID, "Remote Command",
					fmt.Sprintf("WMI Process Create on %s", m[1]))
				tagTask(processResponse.TaskData.Task.ID, "LATERAL",
					fmt.Sprintf("WMI process creation on %s", m[1]))
			}
			return response
		},
		TaskFunctionCreateTasking: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  taskData.Task.ID,
			}
			action, _ := taskData.Args.GetStringArg("action")
			target, _ := taskData.Args.GetStringArg("target")
			display := fmt.Sprintf("action: %s", action)
			if target != "" {
				display += fmt.Sprintf(", host: %s", target)
			}
			response.DisplayParams = &display
			if action == "execute" {
				cmd, _ := taskData.Args.GetStringArg("command")
				host := "localhost"
				if target != "" {
					host = target
				}
				createArtifact(taskData.Task.ID, "API Call", fmt.Sprintf("WMI Win32_Process.Create(%q) on %s", cmd, host))
				logOperationEvent(taskData.Task.ID,
					fmt.Sprintf("[LATERAL] wmi: remote execution on %s from %s", host, taskData.Callback.Host), true)
			}
			return response
		},
	})
}
