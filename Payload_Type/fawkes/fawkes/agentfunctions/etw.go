package agentfunctions

import (
	"fmt"
	"path/filepath"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name: "etw",
		AssociatedBrowserScript: &agentstructs.BrowserScript{
			ScriptPath: filepath.Join(".", "fawkes", "browserscripts", "etw_new.js"),
			Author:     "@galoryber",
		},
		Description:         "Enumerate, stop, blind, query, or enable ETW trace sessions and providers. Use 'sessions'/'providers' for recon, 'query' for details, 'stop'/'blind' for evasion, 'enable' for cleanup.",
		HelpString:          "etw -action <sessions|providers|stop|blind|query|enable> [-session_name <name>] [-provider <guid|shorthand>]",
		Version:             3,
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1082", "T1562.002", "T1562.006"},
		SupportedUIFeatures: []string{},
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_WINDOWS},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:          "action",
				CLIName:       "action",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:       []string{"sessions", "providers", "stop", "blind", "query", "enable"},
				DefaultValue:  "sessions",
				Description:   "Action: sessions (list active traces), providers (enumerate registered), stop (kill a session), blind (disable a provider), query (session details), enable (re-enable a provider)",
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
				Description:   "Target trace session name (required for stop/blind). Examples: EventLog-Security, EventLog-System, Circular Kernel Context Logger",
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
				Description:   "Provider GUID or shorthand name (required for blind). Shorthands: sysmon, amsi, powershell, dotnet, winrm, wmi, security-auditing, kernel-process, kernel-file, kernel-network, kernel-registry",
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
			msg := fmt.Sprintf("OPSEC WARNING: ETW manipulation (action: %s). ", action)
			switch action {
			case "stop":
				msg += "Stopping ETW sessions disables telemetry. EDR products monitor for ETW tampering (T1562.006)."
			case "blind":
				msg += "Blinding ETW providers removes telemetry sources — a well-known evasion technique that EDR vendors specifically detect (T1562.006)."
			default:
				msg += "ETW enumeration is lower risk but unusual behavior may be logged."
			}
			return agentstructs.PTTTaskOPSECPreTaskMessageResponse{
				TaskID: taskData.Task.ID, Success: true,
				OpsecPreBlocked: false, OpsecPreMessage: msg,
				OpsecPreBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
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
			case "blind":
				createArtifact(taskData.Task.ID, "API Call", fmt.Sprintf("ETW EnableTraceEx2(EVENT_CONTROL_CODE_DISABLE_PROVIDER) session=%s provider=%s", sessionName, provider))
			case "enable":
				createArtifact(taskData.Task.ID, "API Call", fmt.Sprintf("ETW EnableTraceEx2(EVENT_CONTROL_CODE_ENABLE_PROVIDER) session=%s provider=%s", sessionName, provider))
			}
			return response
		},
	})
}
