package agentfunctions

import (
	"fmt"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "firewall",
		Description:         "Manage Windows Firewall rules — list, add, delete, enable/disable rules, and check firewall status. Uses HNetCfg.FwPolicy2 COM API.",
		HelpString:          "firewall -action <list|add|delete|enable|disable|status> [-name <rule_name>] [-direction <in|out>] [-rule_action <allow|block>] [-protocol <tcp|udp|any>] [-port <port>] [-program <path>]",
		Version:             1,
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1562.004"}, // Impair Defenses: Disable or Modify System Firewall
		SupportedUIFeatures: []string{},
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_WINDOWS},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:          "action",
				CLIName:       "action",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:       []string{"list", "add", "delete", "enable", "disable", "status"},
				DefaultValue:  "list",
				Description:   "Action: list rules, add/delete a rule, enable/disable a rule, or show firewall status",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: true,
						UIModalPosition:     1,
						GroupName:            "Default",
					},
				},
			},
			{
				Name:          "name",
				CLIName:       "name",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:  "",
				Description:   "Rule name (required for add/delete/enable/disable)",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     2,
						GroupName:            "Default",
					},
				},
			},
			{
				Name:          "direction",
				CLIName:       "direction",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:       []string{"in", "out"},
				DefaultValue:  "in",
				Description:   "Rule direction: inbound (in) or outbound (out)",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     3,
						GroupName:            "Default",
					},
				},
			},
			{
				Name:          "rule_action",
				CLIName:       "rule_action",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:       []string{"allow", "block"},
				DefaultValue:  "allow",
				Description:   "Rule action: allow or block traffic",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     4,
						GroupName:            "Default",
					},
				},
			},
			{
				Name:          "protocol",
				CLIName:       "protocol",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:       []string{"tcp", "udp", "any"},
				DefaultValue:  "any",
				Description:   "Protocol: tcp, udp, or any",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     5,
						GroupName:            "Default",
					},
				},
			},
			{
				Name:          "port",
				CLIName:       "port",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:  "",
				Description:   "Port number or range (e.g., '443', '8080-8090'). Only applies to TCP/UDP.",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     6,
						GroupName:            "Default",
					},
				},
			},
			{
				Name:          "program",
				CLIName:       "program",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:  "",
				Description:   "Program path to associate with rule (e.g., 'C:\\Windows\\System32\\svchost.exe')",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     7,
						GroupName:            "Default",
					},
				},
			},
			{
				Name:          "filter",
				CLIName:       "filter",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:  "",
				Description:   "Filter rules by name substring (for list action)",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     8,
						GroupName:            "Default",
					},
				},
			},
			{
				Name:          "enabled",
				CLIName:       "enabled",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:  "",
				Description:   "Filter by enabled state: 'true' or 'false' (for list action)",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     9,
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
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  taskData.Task.ID,
			}
			action, _ := taskData.Args.GetStringArg("action")
			name, _ := taskData.Args.GetStringArg("name")
			display := fmt.Sprintf("%s", action)
			response.DisplayParams = &display
			switch action {
			case "add":
				createArtifact(taskData.Task.ID, "API Call", fmt.Sprintf("HNetCfg.FwPolicy2.Rules.Add(%s) — Firewall rule created", name))
			case "delete":
				createArtifact(taskData.Task.ID, "API Call", fmt.Sprintf("HNetCfg.FwPolicy2.Rules.Remove(%s) — Firewall rule deleted", name))
			case "enable":
				createArtifact(taskData.Task.ID, "API Call", fmt.Sprintf("HNetCfg.FwPolicy2.Rules.Item(%s).Enabled=true — Firewall rule enabled", name))
			case "disable":
				createArtifact(taskData.Task.ID, "API Call", fmt.Sprintf("HNetCfg.FwPolicy2.Rules.Item(%s).Enabled=false — Firewall rule disabled", name))
			}
			return response
		},
	})
}
