package agentfunctions

import (
	"fmt"
	"path/filepath"
	"strings"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

// isFilePath returns true if the string looks like an absolute file path.
func isFilePath(s string) bool {
	return strings.HasPrefix(s, "/") || strings.HasPrefix(s, "C:\\") || strings.HasPrefix(s, "\\\\")
}

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "eventlog",
		Description:         "Manage system event logs — list, query, clear, info, enable, disable. Windows: wevtapi.dll channels. Linux: journald units and syslog files. macOS: Unified Logging (os_log).",
		HelpString:          "eventlog -action <list|query|clear|info|enable|disable> [-channel <name|unit|subsystem|path>] [-event_id <id>] [-filter <xpath|keyword|timewindow>] [-count <max>]",
		Version:             3,
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1070.001", "T1562.002"}, // T1070.001: Clear Event Logs, T1562.002: Disable Windows Event Logging
		SupportedUIFeatures: []string{},
		AssociatedBrowserScript: &agentstructs.BrowserScript{
			ScriptPath: filepath.Join(".", "fawkes", "browserscripts", "eventlog_new.js"),
			Author:     "@galoryber",
		},
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_WINDOWS, agentstructs.SUPPORTED_OS_LINUX, agentstructs.SUPPORTED_OS_MACOS},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:          "action",
				CLIName:       "action",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:       []string{"list", "query", "clear", "info", "enable", "disable"},
				DefaultValue:  "list",
				Description:   "Action to perform: list, query, clear, info, enable, or disable channels",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: true,
						UIModalPosition:     1,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:          "channel",
				CLIName:       "channel",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:  "",
				Description:   "Windows: channel name (Security, System). Linux: systemd unit (sshd.service) or file path (/var/log/auth.log). macOS: subsystem (com.apple.xpc) or process name (sshd)",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     2,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:          "event_id",
				CLIName:       "event_id",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				DefaultValue:  0,
				Description:   "Windows: filter by Event ID. Linux: filter by syslog priority (0-7, lower=more severe)",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     3,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:          "filter",
				CLIName:       "filter",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:  "",
				Description:   "Filter: Windows: XPath or time window. Linux/macOS: keyword or time window (e.g., '24h', '7d')",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     4,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:          "count",
				CLIName:       "count",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				DefaultValue:  50,
				Description:   "Maximum number of events to return (default: 50)",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     5,
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
			channel, _ := taskData.Args.GetStringArg("channel")
			msg := fmt.Sprintf("OPSEC WARNING: Event log operation (action: %s", action)
			if channel != "" {
				msg += fmt.Sprintf(", channel: %s", channel)
			}
			msg += "). "
			switch action {
			case "clear":
				msg += "Clearing event logs generates Event ID 1102 (audit log cleared) and is a top-tier forensic indicator (T1070.001)."
			case "disable":
				msg += "Disabling event log channels stops telemetry collection — monitored by SIEM and EDR (T1562.002)."
			default:
				msg += "Event log enumeration is lower risk but may be logged by audit policies."
			}
			return agentstructs.PTTTaskOPSECPreTaskMessageResponse{
				TaskID: taskData.Task.ID, Success: true,
				OpsecPreBlocked: false, OpsecPreMessage: msg,
				OpsecPreBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionOPSECPost: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskOPSECPostTaskMessageResponse {
			action, _ := taskData.Args.GetStringArg("action")
			channel, _ := taskData.Args.GetStringArg("channel")
			msg := fmt.Sprintf("OPSEC AUDIT: Event log %s operation completed", action)
			switch action {
			case "clear":
				msg += fmt.Sprintf(". Channel '%s' cleared — Event ID 1102 generated. This is a top forensic indicator (T1070.001).", channel)
			case "disable":
				msg += fmt.Sprintf(". Channel '%s' disabled — telemetry gap created (T1562.002).", channel)
			default:
				msg += ". Enumeration complete — low risk."
			}
			return agentstructs.PTTaskOPSECPostTaskMessageResponse{
				TaskID:              taskData.Task.ID,
				Success:             true,
				OpsecPostBlocked:    false,
				OpsecPostMessage:    msg,
				OpsecPostBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionCreateTasking: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  taskData.Task.ID,
			}
			action, _ := taskData.Args.GetStringArg("action")
			channel, _ := taskData.Args.GetStringArg("channel")
			display := fmt.Sprintf("%s", action)
			if channel != "" {
				display += fmt.Sprintf(", channel: %s", channel)
			}
			response.DisplayParams = &display
			os := taskData.Callback.OS
			switch action {
			case "clear":
				if channel != "" {
					switch os {
					case "Linux":
						createArtifact(taskData.Task.ID, "Process Create", fmt.Sprintf("journalctl --vacuum-time=1s — journal vacuum"))
					case "macOS":
						if isFilePath(channel) {
							createArtifact(taskData.Task.ID, "File Write", fmt.Sprintf("truncate %s — log file cleared", channel))
						}
					default:
						createArtifact(taskData.Task.ID, "API Call", fmt.Sprintf("EvtClearLog(%s) — Windows Event Log cleared", channel))
					}
				}
			case "query":
				if channel != "" && !isFilePath(channel) {
					switch os {
					case "Linux":
						createArtifact(taskData.Task.ID, "Process Create", fmt.Sprintf("journalctl -u %s — query journal", channel))
					case "macOS":
						createArtifact(taskData.Task.ID, "Process Create", fmt.Sprintf("log show --predicate '%s' — query Unified Log", channel))
					}
				}
			case "enable":
				if channel != "" {
					switch os {
					case "macOS":
						createArtifact(taskData.Task.ID, "Process Create", fmt.Sprintf("log config --mode level:debug --subsystem %s", channel))
					case "Windows":
						createArtifact(taskData.Task.ID, "API Call", fmt.Sprintf("EvtSetChannelConfigProperty(%s, Enabled=true)", channel))
					}
				}
			case "disable":
				if channel != "" {
					switch os {
					case "macOS":
						createArtifact(taskData.Task.ID, "Process Create", fmt.Sprintf("log config --mode level:default --subsystem %s", channel))
					case "Windows":
						createArtifact(taskData.Task.ID, "API Call", fmt.Sprintf("EvtSetChannelConfigProperty(%s, Enabled=false)", channel))
					}
				}
			}
			return response
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
			channel, _ := processResponse.TaskData.Args.GetStringArg("channel")
			switch action {
			case "clear":
				if strings.Contains(responseText, "cleared") || strings.Contains(responseText, "Cleared") {
					createArtifact(processResponse.TaskData.Task.ID, "API Call",
						fmt.Sprintf("[EventLog] Channel cleared: %s", channel))
				}
			case "disable":
				if strings.Contains(responseText, "disabled") || strings.Contains(responseText, "Disabled") {
					createArtifact(processResponse.TaskData.Task.ID, "API Call",
						fmt.Sprintf("[EventLog] Channel disabled: %s", channel))
				}
			case "enable":
				if strings.Contains(responseText, "enabled") || strings.Contains(responseText, "Enabled") {
					createArtifact(processResponse.TaskData.Task.ID, "API Call",
						fmt.Sprintf("[EventLog] Channel enabled: %s", channel))
				}
			case "query":
				// Count events returned for tracking
				eventCount := 0
				for _, line := range strings.Split(responseText, "\n") {
					trimmed := strings.TrimSpace(line)
					if strings.HasPrefix(trimmed, "Event ID:") || strings.HasPrefix(trimmed, "event_id:") || strings.Contains(trimmed, "\"EventID\"") {
						eventCount++
					}
				}
				if eventCount > 0 {
					createArtifact(processResponse.TaskData.Task.ID, "Host Discovery",
						fmt.Sprintf("[EventLog] Queried %s: %d events returned", channel, eventCount))
				}
			}
			return response
		},
	})
}
