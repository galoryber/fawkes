package agentfunctions

import (
	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "etw",
		Description:         "Enumerate, stop, or blind ETW trace sessions and providers. Use 'sessions'/'providers' for recon, 'stop' to kill a session, 'blind' to surgically disable a provider within a session.",
		HelpString:          "etw -action <sessions|providers|stop|blind> [-session_name <name>] [-provider <guid|shorthand>]",
		Version:             2,
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
				Choices:       []string{"sessions", "providers", "stop", "blind"},
				DefaultValue:  "sessions",
				Description:   "Action: sessions (list active traces), providers (enumerate registered), stop (kill a session), blind (disable a provider in a session)",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     1,
						GroupName:            "Default",
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
						GroupName:            "Default",
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
						GroupName:            "Default",
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
			return agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  taskData.Task.ID,
			}
		},
	})
}
