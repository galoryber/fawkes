package agentfunctions

import (
	"fmt"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "iptables",
		Description:         "Linux firewall enumeration and rule management via iptables/nftables/ufw (T1562.004)",
		HelpString:          "iptables -action <status|rules|nat|add|delete|flush> [-rule <iptables args>] [-table <filter|nat|mangle>] [-chain <INPUT|OUTPUT|FORWARD>]",
		Version:             1,
		SupportedUIFeatures: []string{},
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1562.004"},
		ScriptOnlyCommand:   false,
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_LINUX},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:             "action",
				ModalDisplayName: "Action",
				CLIName:          "action",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:          []string{"status", "rules", "nat", "add", "delete", "flush"},
				Description:      "Action: status (IP forwarding, tables, ufw), rules (list all rules), nat (NAT rules), add/delete/flush (modify rules)",
				DefaultValue:     "status",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: true,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "rule",
				ModalDisplayName: "Rule",
				CLIName:          "rule",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "iptables rule arguments (e.g., '-A INPUT -p tcp --dport 4444 -j ACCEPT')",
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "table",
				ModalDisplayName: "Table",
				CLIName:          "table",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "iptables table (filter, nat, mangle, raw, security). Default: filter",
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "chain",
				ModalDisplayName: "Chain",
				CLIName:          "chain",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Chain name for flush action (INPUT, OUTPUT, FORWARD, etc.)",
				DefaultValue:     "",
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
			rule, _ := taskData.Args.GetStringArg("rule")
			display := fmt.Sprintf("%s", action)
			response.DisplayParams = &display

			// Report artifacts for modification actions
			switch action {
			case "add":
				createArtifact(taskData.Task.ID, "Process Create", "iptables "+rule)
			case "delete":
				createArtifact(taskData.Task.ID, "Process Create", "iptables "+rule)
			case "flush":
				createArtifact(taskData.Task.ID, "Process Create", "iptables -F")
			case "rules", "nat":
				createArtifact(taskData.Task.ID, "Process Create", "iptables -L")
			}

			return response
		},
	})
}
