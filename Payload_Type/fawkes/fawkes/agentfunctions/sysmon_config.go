package agentfunctions

import (
	"path/filepath"
	"strings"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name: "sysmon-config",
		AssociatedBrowserScript: &agentstructs.BrowserScript{
			ScriptPath: filepath.Join(".", "fawkes", "browserscripts", "sysmonconfig_new.js"),
			Author:     "@galoryber",
		},
		Description:         "Detect Sysmon installation and extract active configuration, event channels, and rule data (T1518.001)",
		HelpString:          "sysmon-config [-action check|rules|events]",
		Version:             1,
		SupportedUIFeatures: []string{},
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1518.001", "T1562.001"},
		ScriptOnlyCommand:   false,
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_WINDOWS},
			FilterCommandAvailabilityByAgentBuildParameters: map[string]string{"selected_os": "Windows"},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:             "action",
				ModalDisplayName: "Action",
				CLIName:          "action",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:          []string{"check", "rules", "events"},
				Description:      "Action to perform: check (detect + config summary), rules (dump raw rules hex), events (list event types and status)",
				DefaultValue:     "check",
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
			msg := "OPSEC WARNING: Sysmon configuration query. "
			switch action {
			case "rules":
				msg += "Dumping Sysmon rules — detectable by Sysmon self-monitoring and may alert security teams (T1518.001)."
			case "events":
				msg += "Listing Sysmon event types — low risk but queryable via audit policies."
			default:
				msg += "Detecting Sysmon installation by reading driver registry and event channels (T1518.001)."
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
				OpsecPostMessage:    "OPSEC AUDIT: Sysmon configuration enumerated. Sysmon config reveals exactly what events are being monitored. This intelligence directly informs evasion strategy.",
				OpsecPostBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionCreateTasking: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  taskData.Task.ID,
			}
			createArtifact(taskData.Task.ID, "Registry Read", "Sysmon service/driver registry keys + event channels")
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
			if strings.Contains(responseText, "Sysmon") || strings.Contains(responseText, "sysmon") {
				tagTask(processResponse.TaskData.Task.ID, "OPSEC",
					"Sysmon detected on target (T1518.001)")
			}
			logOperationEvent(processResponse.TaskData.Task.ID,
				"[RECON] Sysmon configuration enumeration (T1518.001)", false)
			return response
		},
	})
}
