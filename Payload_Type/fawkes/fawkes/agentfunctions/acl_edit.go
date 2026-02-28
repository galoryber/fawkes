package agentfunctions

import (
	"fmt"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "acl-edit",
		Description:         "Read and modify Active Directory object DACLs (access control lists). Add/remove ACEs, grant DCSync rights, GenericAll, WriteDACL. Backup and restore DACLs for clean operations.",
		HelpString:          "acl-edit -action read -server dc01 -target jsmith\nacl-edit -action grant-dcsync -server dc01 -principal attacker -username user@domain -password pass\nacl-edit -action add -server dc01 -target victim -principal attacker -right genericall\nacl-edit -action backup -server dc01 -target jsmith",
		Version:             1,
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1222.001", "T1098", "T1003.006"},
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{
				agentstructs.SUPPORTED_OS_WINDOWS,
				agentstructs.SUPPORTED_OS_LINUX,
				agentstructs.SUPPORTED_OS_MACOS,
			},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:             "action",
				CLIName:          "action",
				ModalDisplayName: "Action",
				Description:      "Operation: read, add, remove, grant-dcsync, grant-genericall, grant-writedacl, backup, restore",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:          []string{"read", "add", "remove", "grant-dcsync", "grant-genericall", "grant-writedacl", "backup", "restore"},
				DefaultValue:     "read",
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
				Name:             "target",
				CLIName:          "target",
				ModalDisplayName: "Target Object",
				Description:      "AD object to read/modify ACL on (sAMAccountName, CN, or full DN)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: true, GroupName: "Default"},
				},
			},
			{
				Name:             "principal",
				CLIName:          "principal",
				ModalDisplayName: "Principal",
				Description:      "Security principal to grant/revoke permissions for (sAMAccountName or SID string)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "right",
				CLIName:          "right",
				ModalDisplayName: "Right",
				Description:      "Permission to grant/revoke: genericall, genericwrite, writedacl, writeowner, forcechangepassword, dcsync, write-member, write-spn, write-keycredentiallink, allextendedrights, writeproperty",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:          []string{"genericall", "genericwrite", "writedacl", "writeowner", "forcechangepassword", "dcsync", "ds-replication-get-changes-all", "write-member", "write-spn", "write-keycredentiallink", "allextendedrights", "writeproperty"},
				DefaultValue:     "genericall",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "backup",
				CLIName:          "backup",
				ModalDisplayName: "Backup Data",
				Description:      "Base64-encoded security descriptor (for restore action, from backup output)",
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
				Description:      "LDAP bind username (e.g., DOMAIN\\user or user@domain.local)",
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
				Name:             "base_dn",
				CLIName:          "base_dn",
				ModalDisplayName: "Base DN",
				Description:      "LDAP search base (auto-detected if empty)",
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
				Description:      "LDAP port (default: 389, TLS: 636)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				DefaultValue:     389,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "use_tls",
				CLIName:          "use_tls",
				ModalDisplayName: "Use TLS",
				Description:      "Use LDAPS (TLS) connection",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_BOOLEAN,
				DefaultValue:     false,
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
		TaskFunctionCreateTasking: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  taskData.Task.ID,
			}

			action, _ := taskData.Args.GetStringArg("action")
			target, _ := taskData.Args.GetStringArg("target")
			principal, _ := taskData.Args.GetStringArg("principal")
			right, _ := taskData.Args.GetStringArg("right")

			switch action {
			case "read", "backup":
				displayStr := fmt.Sprintf("acl-edit %s on %s", action, target)
				response.DisplayParams = &displayStr
			case "grant-dcsync", "grant-genericall", "grant-writedacl":
				displayStr := fmt.Sprintf("acl-edit %s: %s → %s", action, principal, target)
				response.DisplayParams = &displayStr
			case "add", "remove":
				displayStr := fmt.Sprintf("acl-edit %s %s: %s → %s", action, right, principal, target)
				response.DisplayParams = &displayStr
			case "restore":
				displayStr := fmt.Sprintf("acl-edit restore DACL on %s", target)
				response.DisplayParams = &displayStr
			}

			return response
		},
	})
}
