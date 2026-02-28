package agentfunctions

import (
	"fmt"

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
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
		},
		TaskFunctionParseArgString: func(args *agentstructs.PTTaskMessageArgsData, input string) error {
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
