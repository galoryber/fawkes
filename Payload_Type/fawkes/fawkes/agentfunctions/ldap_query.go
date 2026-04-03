package agentfunctions

import (
	"fmt"
	"path/filepath"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
	"github.com/MythicMeta/MythicContainer/mythicrpc"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "ldap-query",
		Description:         "Query Active Directory via LDAP. Supports preset queries (users, computers, groups, domain-admins, admins, SPNs, AS-REP roastable, disabled, GPOs, OUs, password-never-expires, trusts, unconstrained/constrained delegation) and custom LDAP filters.",
		HelpString:          "ldap-query -action users -server 192.168.1.1\nldap-query -action trusts -server dc01\nldap-query -action unconstrained -server dc01\nldap-query -action constrained -server dc01\nldap-query -action query -server dc01 -filter \"(servicePrincipalName=*MSSQLSvc*)\"",
		Version:             3,
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1087.002", "T1069.002"},
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{
				agentstructs.SUPPORTED_OS_WINDOWS,
				agentstructs.SUPPORTED_OS_LINUX,
				agentstructs.SUPPORTED_OS_MACOS,
			},
		},
		AssociatedBrowserScript: &agentstructs.BrowserScript{ScriptPath: filepath.Join(".", "fawkes", "browserscripts", "ldap_query_new.js"), Author: "@galoryber"},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:             "action",
				CLIName:          "action",
				ModalDisplayName: "Query Type",
				Description:      "Preset query or custom filter",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:          []string{"users", "computers", "groups", "domain-admins", "spns", "asrep", "admins", "disabled", "gpo", "ou", "password-never-expires", "trusts", "unconstrained", "constrained", "dacl", "query"},
				DefaultValue:     "users",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: true, GroupName: "Default"},
				},
			},
			{
				Name:             "server",
				CLIName:          "server",
				ModalDisplayName: "Domain Controller",
				Description:      "DC IP address or hostname",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: true, GroupName: "Default"},
				},
			},
			{
				Name:             "filter",
				CLIName:          "filter",
				ModalDisplayName: "LDAP Filter",
				Description:      "Custom LDAP filter (required when action=query)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "base_dn",
				CLIName:          "base_dn",
				ModalDisplayName: "Base DN",
				Description:      "LDAP search base (auto-detected from RootDSE if empty)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "username",
				CLIName:          "username",
				ModalDisplayName: "Username",
				Description:      "LDAP bind username (e.g., DOMAIN\\user or user@domain.local). Empty for anonymous bind.",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "password",
				CLIName:          "password",
				ModalDisplayName: "Password",
				Description:      "LDAP bind password",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "port",
				CLIName:          "port",
				ModalDisplayName: "Port",
				Description:      "LDAP port (default: 389 for LDAP, 636 for LDAPS)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				DefaultValue:     389,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "limit",
				CLIName:          "limit",
				ModalDisplayName: "Result Limit",
				Description:      "Maximum number of results (default: 100)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				DefaultValue:     100,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "use_tls",
				CLIName:          "use_tls",
				ModalDisplayName: "Use LDAPS",
				Description:      "Use TLS/LDAPS (port 636) instead of plain LDAP (port 389)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_BOOLEAN,
				DefaultValue:     false,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "timeout",
				CLIName:          "timeout",
				ModalDisplayName: "Timeout (seconds)",
				Description:      "Operation timeout in seconds (default: 120). Prevents agent hangs on unreachable targets.",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				DefaultValue:     120,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
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
			server, _ := taskData.Args.GetStringArg("server")
			msg := fmt.Sprintf("OPSEC WARNING: LDAP query (%s) against %s.", action, server)
			switch action {
			case "domain-admins", "admins", "spns", "asrep":
				msg += " Querying privileged/sensitive attributes — may trigger AD honeypot or LDAP monitoring rules for reconnaissance."
			case "dacl":
				msg += " DACL enumeration reads security descriptors — some EDR products monitor bulk DACL reads as BloodHound-like behavior."
			default:
				msg += " LDAP queries generate directory service access logs (Event ID 4662). High-volume queries may trigger anomaly detection."
			}
			return agentstructs.PTTTaskOPSECPreTaskMessageResponse{
				TaskID:             taskData.Task.ID,
				Success:            true,
				OpsecPreBlocked:    false,
				OpsecPreMessage:    msg,
				OpsecPreBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionCreateTasking: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  taskData.Task.ID,
			}

			action, _ := taskData.Args.GetStringArg("action")
			server, _ := taskData.Args.GetStringArg("server")
			filter, _ := taskData.Args.GetStringArg("filter")

			displayMsg := fmt.Sprintf("LDAP %s on %s", action, server)
			if action == "query" && filter != "" {
				displayMsg += fmt.Sprintf(" filter=%s", filter)
			} else if action == "dacl" && filter != "" {
				displayMsg = fmt.Sprintf("LDAP DACL on %s target=%s", server, filter)
			}
			response.DisplayParams = &displayMsg

			mythicrpc.SendMythicRPCArtifactCreate(mythicrpc.MythicRPCArtifactCreateMessage{
				TaskID:           taskData.Task.ID,
				BaseArtifactType: "API Call",
				ArtifactMessage:  fmt.Sprintf("LDAP query: %s on %s", action, server),
			})

			return response
		},
	})
}
