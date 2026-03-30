package agentfunctions

import (
	"path/filepath"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name: "av-detect",
		AssociatedBrowserScript: &agentstructs.BrowserScript{
			ScriptPath: filepath.Join(".", "fawkes", "browserscripts", "avdetect_new.js"),
			Author:     "@galoryber",
		},
		Description:         "Detect installed AV/EDR/security products by scanning running processes and optionally checking kernel modules, system extensions, LaunchDaemons, application bundles, and config directories (--deep).",
		HelpString:          "av-detect [-deep true]",
		Version:             3,
		MitreAttackMappings: []string{"T1518.001"}, // Software Discovery: Security Software Discovery
		SupportedUIFeatures: []string{},
		Author:              "@galoryber",
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_LINUX, agentstructs.SUPPORTED_OS_MACOS, agentstructs.SUPPORTED_OS_WINDOWS},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:          "deep",
				CLIName:       "deep",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_BOOLEAN,
				DefaultValue:  false,
				Description:   "Enable deep scanning: check kernel modules, systemd units, and config directories beyond process enumeration (Linux/macOS).",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
		},
		TaskFunctionParseArgString: func(args *agentstructs.PTTaskMessageArgsData, input string) error {
			return args.LoadArgsFromJSONString(input)
		},
		TaskFunctionParseArgDictionary: func(args *agentstructs.PTTaskMessageArgsData, input map[string]interface{}) error {
			return args.LoadArgsFromDictionary(input)
		},
		TaskFunctionOPSECPre: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTTaskOPSECPreTaskMessageResponse {
			return agentstructs.PTTTaskOPSECPreTaskMessageResponse{
				TaskID: taskData.Task.ID, Success: true,
				OpsecPreBlocked: false,
				OpsecPreMessage:    "OPSEC WARNING: Detects installed AV/EDR products by scanning running processes (T1518.001). Process enumeration targeting security tool names is a known attacker behavior. Some EDR products monitor for their own process being queried.",
				OpsecPreBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionCreateTasking: func(task *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			return agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  task.Task.ID,
			}
		},
	})
}
