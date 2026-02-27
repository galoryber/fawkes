package agentfunctions

import (
	"fmt"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
	"github.com/MythicMeta/MythicContainer/mythicrpc"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "ldap-write",
		Description:         "Modify Active Directory objects via LDAP. Add/remove group members, set attributes, manage SPNs, enable/disable accounts, set passwords, create machine accounts, RBCD delegation, shadow credentials, delete objects.",
		HelpString:          "ldap-write -action add-member -server dc01 -target jsmith -group \"Domain Admins\"\nldap-write -action shadow-cred -server dc01 -target victim -username user@domain -password pass\nldap-write -action set-rbcd -server dc01 -target victim -value FAKEPC01$",
		Version:             1,
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1098", "T1098.005", "T1134.001", "T1136.002", "T1556.006"},
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
				Description:      "Operation: add-member, remove-member, set-attr, add-attr, remove-attr, set-spn, disable, enable, set-password, add-computer, delete-object, set-rbcd, clear-rbcd, shadow-cred, clear-shadow-cred",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:          []string{"add-member", "remove-member", "set-attr", "add-attr", "remove-attr", "set-spn", "disable", "enable", "set-password", "add-computer", "delete-object", "set-rbcd", "clear-rbcd", "shadow-cred", "clear-shadow-cred"},
				DefaultValue:     "add-member",
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
				Description:      "Object to modify (sAMAccountName, CN, or full DN)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: true, GroupName: "Default"},
				},
			},
			{
				Name:             "group",
				CLIName:          "group",
				ModalDisplayName: "Group",
				Description:      "Group name (for add-member/remove-member actions)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "attr",
				CLIName:          "attr",
				ModalDisplayName: "Attribute",
				Description:      "LDAP attribute name (for set-attr/add-attr/remove-attr)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "value",
				CLIName:          "value",
				ModalDisplayName: "Value",
				Description:      "Attribute value (for set-attr/add-attr/remove-attr/set-spn/set-password)",
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
				Description:      "LDAP port (default: 389, 636 for LDAPS)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				DefaultValue:     389,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "use_tls",
				CLIName:          "use_tls",
				ModalDisplayName: "Use LDAPS",
				Description:      "Use TLS/LDAPS (required for set-password)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_BOOLEAN,
				DefaultValue:     false,
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
			server, _ := taskData.Args.GetStringArg("server")
			target, _ := taskData.Args.GetStringArg("target")
			group, _ := taskData.Args.GetStringArg("group")
			attr, _ := taskData.Args.GetStringArg("attr")
			value, _ := taskData.Args.GetStringArg("value")

			displayMsg := fmt.Sprintf("LDAP %s %s", action, target)
			artifactMsg := fmt.Sprintf("LDAP modify: %s on %s (server: %s)", action, target, server)

			switch action {
			case "add-member", "remove-member":
				displayMsg = fmt.Sprintf("LDAP %s %s → %s", action, target, group)
				artifactMsg = fmt.Sprintf("LDAP %s: %s → %s (server: %s)", action, target, group, server)
			case "set-attr", "add-attr", "remove-attr":
				displayMsg = fmt.Sprintf("LDAP %s %s.%s = %s", action, target, attr, value)
			case "set-spn":
				displayMsg = fmt.Sprintf("LDAP set-spn %s = %s", target, value)
			case "set-password":
				displayMsg = fmt.Sprintf("LDAP set-password %s", target)
			case "add-computer":
				displayMsg = fmt.Sprintf("LDAP add-computer %s", target)
				artifactMsg = fmt.Sprintf("LDAP add computer account: %s (server: %s)", target, server)
			case "delete-object":
				displayMsg = fmt.Sprintf("LDAP delete-object %s", target)
				artifactMsg = fmt.Sprintf("LDAP delete object: %s (server: %s)", target, server)
			case "set-rbcd":
				displayMsg = fmt.Sprintf("LDAP set-rbcd %s ← %s", target, value)
				artifactMsg = fmt.Sprintf("LDAP set RBCD: %s delegated to %s (server: %s)", target, value, server)
			case "clear-rbcd":
				displayMsg = fmt.Sprintf("LDAP clear-rbcd %s", target)
				artifactMsg = fmt.Sprintf("LDAP clear RBCD: %s (server: %s)", target, server)
			case "shadow-cred":
				displayMsg = fmt.Sprintf("LDAP shadow-cred %s", target)
				artifactMsg = fmt.Sprintf("LDAP write msDS-KeyCredentialLink: %s (server: %s)", target, server)
			case "clear-shadow-cred":
				displayMsg = fmt.Sprintf("LDAP clear-shadow-cred %s", target)
				artifactMsg = fmt.Sprintf("LDAP clear msDS-KeyCredentialLink: %s (server: %s)", target, server)
			}

			response.DisplayParams = &displayMsg

			mythicrpc.SendMythicRPCArtifactCreate(mythicrpc.MythicRPCArtifactCreateMessage{
				TaskID:           taskData.Task.ID,
				BaseArtifactType: "API Call",
				ArtifactMessage:  artifactMsg,
			})

			return response
		},
	})
}
