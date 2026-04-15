package agentfunctions

import (
	"fmt"
	"path/filepath"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
	"github.com/MythicMeta/MythicContainer/mythicrpc"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name: "firewall",
		AssociatedBrowserScript: &agentstructs.BrowserScript{
			ScriptPath: filepath.Join(".", "fawkes", "browserscripts", "firewall_new.js"),
			Author:     "@galoryber",
		},
		Description:         "Manage firewall rules — list, add, delete, enable/disable rules, and check firewall status. Windows: HNetCfg.FwPolicy2 COM. macOS: pf/ALF. Linux: iptables/nftables (auto-detected).",
		HelpString:          "firewall -action <list|add|delete|enable|disable|status> [-name <rule_name>] [-direction <in|out>] [-rule_action <allow|block>] [-protocol <tcp|udp|any>] [-port <port>] [-program <path>]",
		Version:             3,
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1562.004"}, // Impair Defenses: Disable or Modify System Firewall
		SupportedUIFeatures: []string{},
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_WINDOWS, agentstructs.SUPPORTED_OS_MACOS, agentstructs.SUPPORTED_OS_LINUX},
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
						GroupName:           "Default",
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
						GroupName:           "Default",
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
						GroupName:           "Default",
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
						GroupName:           "Default",
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
						GroupName:           "Default",
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
						GroupName:           "Default",
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
						GroupName:           "Default",
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
						GroupName:           "Default",
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
			msg := fmt.Sprintf("OPSEC WARNING: Firewall modification (action: %s). ", action)
			switch action {
			case "add":
				msg += "Adding firewall rules modifies security policy — generates event logs and may trigger change detection (T1562.004)."
			case "delete":
				msg += "Deleting firewall rules weakens security posture — commonly monitored by SIEM as defense evasion (T1562.004)."
			case "disable":
				msg += "Disabling firewall rules is a high-visibility security change (T1562.004)."
			default:
				msg += "Firewall enumeration is lower risk but may be logged by audit policies."
			}
			return agentstructs.PTTTaskOPSECPreTaskMessageResponse{
				TaskID: taskData.Task.ID, Success: true,
				OpsecPreBlocked: false, OpsecPreMessage: msg,
				OpsecPreBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionOPSECPost: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskOPSECPostTaskMessageResponse {
			action, _ := taskData.Args.GetStringArg("action")
			name, _ := taskData.Args.GetStringArg("name")
			msg := fmt.Sprintf("OPSEC AUDIT: Firewall %s operation completed", action)
			switch action {
			case "add":
				msg += fmt.Sprintf(". Rule '%s' created — verify no alerting triggered (T1562.004).", name)
			case "delete":
				msg += fmt.Sprintf(". Rule '%s' removed — security posture modified (T1562.004).", name)
			case "disable":
				msg += fmt.Sprintf(". Rule '%s' disabled — defense weakened (T1562.004).", name)
			default:
				msg += ". Enumeration complete — low risk."
			}
			return agentstructs.PTTaskOPSECPostTaskMessageResponse{
				TaskID:              taskData.Task.ID,
				Success:             true,
				OpsecPostBlocked:    false,
				OpsecPostMessage:    msg,
				OpsecPostBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionCreateTasking: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  taskData.Task.ID,
			}
			action, _ := taskData.Args.GetStringArg("action")
			name, _ := taskData.Args.GetStringArg("name")
			program, _ := taskData.Args.GetStringArg("program")
			display := fmt.Sprintf("%s", action)
			response.DisplayParams = &display
			osName := taskData.Callback.OS
			switch action {
			case "add":
				switch osName {
				case "macOS":
					createArtifact(taskData.Task.ID, "Process Create", fmt.Sprintf("socketfilterfw --add %s", program))
				case "Linux":
					createArtifact(taskData.Task.ID, "Process Create", fmt.Sprintf("iptables/nft — add rule %s", name))
				default:
					createArtifact(taskData.Task.ID, "API Call", fmt.Sprintf("HNetCfg.FwPolicy2.Rules.Add(%s) — Firewall rule created", name))
				}
			case "delete":
				switch osName {
				case "macOS":
					createArtifact(taskData.Task.ID, "Process Create", fmt.Sprintf("socketfilterfw --remove %s", program))
				case "Linux":
					createArtifact(taskData.Task.ID, "Process Create", fmt.Sprintf("iptables/nft — delete rule %s", name))
				default:
					createArtifact(taskData.Task.ID, "API Call", fmt.Sprintf("HNetCfg.FwPolicy2.Rules.Remove(%s) — Firewall rule deleted", name))
				}
			case "enable":
				switch osName {
				case "macOS":
					createArtifact(taskData.Task.ID, "Process Create", "socketfilterfw --setglobalstate on")
				default:
					createArtifact(taskData.Task.ID, "API Call", fmt.Sprintf("HNetCfg.FwPolicy2.Rules.Item(%s).Enabled=true — Firewall rule enabled", name))
				}
			case "disable":
				switch osName {
				case "macOS":
					createArtifact(taskData.Task.ID, "Process Create", "socketfilterfw --setglobalstate off")
				default:
					createArtifact(taskData.Task.ID, "API Call", fmt.Sprintf("HNetCfg.FwPolicy2.Rules.Item(%s).Enabled=false — Firewall rule disabled", name))
				}
			case "list", "status":
				if osName == "Linux" {
					createArtifact(taskData.Task.ID, "Process Create", "iptables/nft — list rules")
				}
			}
			return response
		},
		TaskFunctionProcessResponse: func(processResponse agentstructs.PtTaskProcessResponseMessage) agentstructs.PTTaskProcessResponseMessageResponse {
			response := agentstructs.PTTaskProcessResponseMessageResponse{
				TaskID:  processResponse.TaskData.Task.ID,
				Success: true,
			}
			action, _ := processResponse.TaskData.Args.GetStringArg("action")

			switch action {
			case "add", "delete", "enable", "disable":
				// Track firewall modifications as defense evasion artifacts
				name, _ := processResponse.TaskData.Args.GetStringArg("name")
				mythicrpc.SendMythicRPCArtifactCreate(mythicrpc.MythicRPCArtifactCreateMessage{
					TaskID:           processResponse.TaskData.Task.ID,
					BaseArtifactType: "Configuration",
					ArtifactMessage:  fmt.Sprintf("Firewall rule %s: %s on %s", action, name, processResponse.TaskData.Callback.Host),
				})
				logOperationEvent(processResponse.TaskData.Task.ID,
					fmt.Sprintf("[DEFENSE EVASION] Firewall rule %s: %s on %s", action, name, processResponse.TaskData.Callback.Host), true)
			case "list", "status":
				mythicrpc.SendMythicRPCArtifactCreate(mythicrpc.MythicRPCArtifactCreateMessage{
					TaskID:           processResponse.TaskData.Task.ID,
					BaseArtifactType: "Configuration",
					ArtifactMessage:  fmt.Sprintf("Firewall %s enumerated on %s", action, processResponse.TaskData.Callback.Host),
				})
			}
			return response
		},
	})
}
