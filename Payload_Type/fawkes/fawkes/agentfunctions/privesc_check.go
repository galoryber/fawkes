package agentfunctions

import (
	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "privesc-check",
		Description:         "Privilege escalation enumeration. Windows: token privileges, unquoted services, AlwaysInstallElevated, auto-logon, UAC. Linux: SUID/SGID, capabilities, sudo, containers. macOS: LaunchDaemons, TCC, dylib hijacking, SIP (T1548)",
		HelpString:          "privesc-check -action <all|...> (Windows: privileges, services, registry, uac, unattend. Linux: suid, capabilities, sudo, container. macOS: launchdaemons, tcc, dylib, sip. Shared: all, writable)",
		Version:             3,
		SupportedUIFeatures: []string{},
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1548", "T1548.001", "T1548.002", "T1574.009", "T1552.001", "T1613", "T1082"},
		ScriptOnlyCommand:   false,
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_WINDOWS, agentstructs.SUPPORTED_OS_LINUX, agentstructs.SUPPORTED_OS_MACOS},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:             "action",
				ModalDisplayName: "Action",
				CLIName:          "action",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:          []string{"all", "privileges", "services", "registry", "uac", "unattend", "writable", "suid", "sudo", "capabilities", "container", "launchdaemons", "tcc", "dylib", "sip"},
				Description:      "Check to perform. Windows: privileges, services, registry, uac, unattend. Linux: suid, capabilities, sudo, container. macOS: launchdaemons, tcc, dylib, sip. Shared: all, writable",
				DefaultValue:     "all",
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
		TaskFunctionCreateTasking: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  taskData.Task.ID,
			}
			action, _ := taskData.Args.GetStringArg("action")
			if action != "" && action != "all" {
				response.DisplayParams = &action
			}
			return response
		},
	})
}
