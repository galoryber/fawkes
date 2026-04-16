package agentfunctions

import (
	"fmt"
	"path/filepath"
	"regexp"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func formatWMIOPSEC(action, host string) string {
	if action == "check" {
		return fmt.Sprintf("OPSEC INFO: WMI check on %s. Validates port 135 and WMI connectivity. Generates TCP connection + COM call — low footprint, no process creation.", host)
	}
	if host != "" && host != "." && host != "localhost" {
		return fmt.Sprintf("OPSEC WARNING: Remote WMI %s on %s. Generates WMI activity events (Event ID 5857-5861) and network traffic on TCP 135/dynamic RPC. Remote WMI execution is a common lateral movement indicator.", action, host)
	}
	return fmt.Sprintf("OPSEC WARNING: Local WMI %s. Generates WMI activity events (Event ID 5857-5861). WMI is commonly monitored for persistence and execution.", action)
}

var wmiProcessCreateRegex = regexp.MustCompile(`WMI Process Create on (\S+?):`)

func extractWMIHost(responseText string) (string, bool) {
	m := wmiProcessCreateRegex.FindStringSubmatch(responseText)
	if len(m) > 1 {
		return m[1], true
	}
	return "", false
}

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "wmi",
		Description:         "Execute WMI queries, process creation, and staged file transfer via COM API (T1047, T1570)",
		HelpString:          "wmi -action <execute|query|process-list|os-info|upload|exec-staged|check> [-target <host>] [-command <cmd>] [-query <wmic_query>] [-local_path <path>] [-remote_path <path>] [-method <certutil|powershell>] [-cleanup <true|false>]",
		Version:             3,
		SupportedUIFeatures: []string{},
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1047", "T1570"},
		ScriptOnlyCommand:   false,
		AssociatedBrowserScript: &agentstructs.BrowserScript{ScriptPath: filepath.Join(".", "fawkes", "browserscripts", "wmi_new.js"), Author: "@galoryber"},
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS:                []string{agentstructs.SUPPORTED_OS_WINDOWS},
			CommandCanOnlyBeLoadedLater: true,
			FilterCommandAvailabilityByAgentBuildParameters: map[string]string{"selected_os": "Windows"},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:             "action",
				ModalDisplayName: "Action",
				CLIName:          "action",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:          []string{"execute", "query", "process-list", "os-info", "upload", "exec-staged", "check"},
				Description:      "execute: create a process, query: run wmic query, process-list: list processes, os-info: OS details, upload: stage file on remote host, exec-staged: upload + execute + optional cleanup, check: validate WMI prerequisites",
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
			{
				Name:             "local_path",
				CLIName:          "local_path",
				ModalDisplayName: "Local File Path",
				Description:      "Path to file on agent filesystem to stage on remote host (for upload/exec-staged actions)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "remote_path",
				CLIName:          "remote_path",
				ModalDisplayName: "Remote File Path",
				Description:      "Destination path on remote host (default: C:\\Windows\\Temp\\<random>.exe)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "method",
				CLIName:          "method",
				ModalDisplayName: "Staging Method",
				Description:      "How to transfer the file: certutil (base64 chunks + decode) or powershell (single command, <150KB files)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:          []string{"certutil", "powershell"},
				DefaultValue:     "certutil",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "cleanup",
				CLIName:          "cleanup",
				ModalDisplayName: "Auto-Cleanup",
				Description:      "Remove staged file after execution (exec-staged only, default: false)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_BOOLEAN,
				DefaultValue:     false,
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
			msg := formatWMIOPSEC(action, host)
			if ctx := identityContextForOPSEC(taskData.Callback.Description); ctx != "" {
				msg += " [Identity: " + ctx + "]"
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
			if host, ok := extractWMIHost(responseText); ok {
				createArtifact(processResponse.TaskData.Task.ID, "Remote Command",
					fmt.Sprintf("WMI Process Create on %s", host))
				tagTask(processResponse.TaskData.Task.ID, "LATERAL",
					fmt.Sprintf("WMI process creation on %s", host))
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
