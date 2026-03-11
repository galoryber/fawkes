package agentfunctions

import (
	"fmt"
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
		Description:         "Manage system event logs — list, query, clear, info, enable, disable. Windows: wevtapi.dll channels. Linux: journald units and syslog files.",
		HelpString:          "eventlog -action <list|query|clear|info|enable|disable> [-channel <name|unit|path>] [-event_id <id>] [-filter <xpath|keyword|timewindow>] [-count <max>]",
		Version:             2,
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1070.001", "T1562.002"}, // T1070.001: Clear Event Logs, T1562.002: Disable Windows Event Logging
		SupportedUIFeatures: []string{},
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_WINDOWS, agentstructs.SUPPORTED_OS_LINUX},
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
				Description:   "Windows: channel name (Security, System). Linux: systemd unit (sshd.service) or file path (/var/log/auth.log)",
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
				Description:   "Filter: Windows: XPath or time window. Linux: keyword or time window (e.g., '24h', '7d')",
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
					if os == "Linux" {
						createArtifact(taskData.Task.ID, "Process Create", fmt.Sprintf("journalctl --vacuum-time=1s — journal vacuum"))
					} else {
						createArtifact(taskData.Task.ID, "API Call", fmt.Sprintf("EvtClearLog(%s) — Windows Event Log cleared", channel))
					}
				}
			case "query":
				if os == "Linux" && channel != "" && !isFilePath(channel) {
					createArtifact(taskData.Task.ID, "Process Create", fmt.Sprintf("journalctl -u %s — query journal", channel))
				}
			case "enable":
				if channel != "" && os != "Linux" {
					createArtifact(taskData.Task.ID, "API Call", fmt.Sprintf("EvtSetChannelConfigProperty(%s, Enabled=true)", channel))
				}
			case "disable":
				if channel != "" && os != "Linux" {
					createArtifact(taskData.Task.ID, "API Call", fmt.Sprintf("EvtSetChannelConfigProperty(%s, Enabled=false)", channel))
				}
			}
			return response
		},
	})
}
