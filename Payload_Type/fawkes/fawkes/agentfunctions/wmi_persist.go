package agentfunctions

import (
	"fmt"
	"path/filepath"
	"strings"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "wmi-persist",
		Description:         "Install, remove, or list WMI Event Subscription persistence. Creates persistent event filter + command-line consumer that survives reboots.",
		HelpString:          "wmi-persist -action install -name backdoor -trigger logon -command \"C:\\payload.exe\"\nwmi-persist -action list\nwmi-persist -action remove -name backdoor",
		Version:             1,
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1546.003"},
		AssociatedBrowserScript: &agentstructs.BrowserScript{
			ScriptPath: filepath.Join(".", "fawkes", "browserscripts", "wmipersist_new.js"),
			Author:     "@galoryber",
		},
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{
				agentstructs.SUPPORTED_OS_WINDOWS,
			},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:             "action",
				CLIName:          "action",
				ModalDisplayName: "Action",
				Description:      "install: create WMI event subscription, remove: delete subscription, list: show all subscriptions",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:          []string{"install", "remove", "list"},
				DefaultValue:     "list",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: true, GroupName: "Default"},
				},
			},
			{
				Name:             "name",
				CLIName:          "name",
				ModalDisplayName: "Subscription Name",
				Description:      "Name prefix for the event filter, consumer, and binding",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "command",
				CLIName:          "command",
				ModalDisplayName: "Command",
				Description:      "Command line to execute when event fires (full path recommended)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "trigger",
				CLIName:          "trigger",
				ModalDisplayName: "Trigger Type",
				Description:      "logon: on user login, startup: after boot, interval: periodic timer, process: when specific process starts",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:          []string{"logon", "startup", "interval", "process"},
				DefaultValue:     "logon",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "interval_sec",
				CLIName:          "interval_sec",
				ModalDisplayName: "Interval (seconds)",
				Description:      "Interval in seconds for periodic trigger (minimum 10, default 300)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				DefaultValue:     300,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "process_name",
				CLIName:          "process_name",
				ModalDisplayName: "Process Name",
				Description:      "Process name to trigger on (e.g., notepad.exe) — only for process trigger",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "target",
				CLIName:          "target",
				ModalDisplayName: "Remote Host",
				Description:      "Remote host for WMI connection (leave empty for localhost)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:     "",
				DynamicQueryFunction: getActiveHostList,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
		},
		TaskFunctionOPSECPre: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTTaskOPSECPreTaskMessageResponse {
			action, _ := taskData.Args.GetStringArg("action")
			name, _ := taskData.Args.GetStringArg("name")
			msg := fmt.Sprintf("OPSEC WARNING: WMI event subscription operation (%s", action)
			if name != "" {
				msg += fmt.Sprintf(", name: %s", name)
			}
			msg += "). "
			switch action {
			case "install":
				msg += "Creates WMI EventFilter, CommandLineEventConsumer, and FilterToConsumerBinding. " +
					"Detectable by monitoring WMI repository changes and Sysmon Event ID 19/20/21."
			case "remove":
				msg += "Removes WMI event subscription — cleanup operation."
			default:
				msg += "Enumerating WMI subscriptions — low detection risk."
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
			action, _ := taskData.Args.GetStringArg("action")
			name, _ := taskData.Args.GetStringArg("name")
			msg := fmt.Sprintf("OPSEC AUDIT: wmi-persist %s", action)
			if name != "" {
				msg += fmt.Sprintf(" (name: %s)", name)
			}
			msg += " configured. WMI repository artifacts will be created."
			return agentstructs.PTTaskOPSECPostTaskMessageResponse{
				TaskID:              taskData.Task.ID,
				Success:             true,
				OpsecPostBlocked:    false,
				OpsecPostMessage:    msg,
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
			action, _ := processResponse.TaskData.Args.GetStringArg("action")
			switch action {
			case "list":
				// Parse WMI subscriptions from text output — look for [N] prefixed entries
				for _, line := range strings.Split(responseText, "\n") {
					trimmed := strings.TrimSpace(line)
					if len(trimmed) > 3 && trimmed[0] == '[' {
						// Lines like: [1] MyFilter_Filter
						closeBracket := strings.Index(trimmed, "]")
						if closeBracket > 0 && closeBracket+2 < len(trimmed) {
							entryName := strings.TrimSpace(trimmed[closeBracket+1:])
							createArtifact(processResponse.TaskData.Task.ID, "Persistence Mechanism",
								fmt.Sprintf("WMI Subscription: %s", entryName))
						}
					}
				}
			case "install":
				name, _ := processResponse.TaskData.Args.GetStringArg("name")
				trigger, _ := processResponse.TaskData.Args.GetStringArg("trigger")
				if strings.Contains(responseText, "Created") || strings.Contains(responseText, "installed") || strings.Contains(responseText, "Success") {
					createArtifact(processResponse.TaskData.Task.ID, "Persistence Mechanism",
						fmt.Sprintf("[Persistence Installed] WMI event subscription: %s (trigger: %s)", name, trigger))
				}
			case "remove":
				name, _ := processResponse.TaskData.Args.GetStringArg("name")
				if strings.Contains(responseText, "Removed") || strings.Contains(responseText, "removed") || strings.Contains(responseText, "Deleted") {
					createArtifact(processResponse.TaskData.Task.ID, "Persistence Mechanism",
						fmt.Sprintf("[Persistence Removed] WMI event subscription: %s", name))
				}
			}
			return response
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
			name, _ := taskData.Args.GetStringArg("name")
			trigger, _ := taskData.Args.GetStringArg("trigger")

			var displayMsg string
			switch action {
			case "install":
				displayMsg = fmt.Sprintf("wmi-persist install '%s' (trigger: %s)", name, trigger)
			case "remove":
				displayMsg = fmt.Sprintf("wmi-persist remove '%s'", name)
			default:
				displayMsg = "wmi-persist list"
			}
			response.DisplayParams = &displayMsg

			if action == "install" {
				command, _ := taskData.Args.GetStringArg("command")
				createArtifact(taskData.Task.ID, "API Call", fmt.Sprintf("WMI EventSubscription creation: %s (trigger: %s, command: %s)", name, trigger, command))
			} else if action == "remove" {
				createArtifact(taskData.Task.ID, "API Call", fmt.Sprintf("WMI EventSubscription removal: %s", name))
			}

			return response
		},
	})
}
