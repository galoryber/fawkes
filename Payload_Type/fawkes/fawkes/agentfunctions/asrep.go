package agentfunctions

import (
	"fmt"
	"path/filepath"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
	"github.com/MythicMeta/MythicContainer/mythicrpc"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "asrep-roast",
		Description:         "Request AS-REP tickets for accounts without Kerberos pre-authentication and extract hashes for offline cracking. Auto-enumerates roastable accounts via LDAP or targets a specific account.",
		HelpString:          "asrep-roast -server 192.168.1.1 -username user@domain.local -password pass\nasrep-roast -server dc01 -realm DOMAIN.LOCAL -username user@domain.local -password pass -account targetuser",
		Version:             1,
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1558.004"},
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{
				agentstructs.SUPPORTED_OS_WINDOWS,
				agentstructs.SUPPORTED_OS_LINUX,
				agentstructs.SUPPORTED_OS_MACOS,
			},
		},
		AssociatedBrowserScript: &agentstructs.BrowserScript{ScriptPath: filepath.Join(".", "fawkes", "browserscripts", "asrep_new.js"), Author: "@galoryber"},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:             "server",
				CLIName:          "server",
				ModalDisplayName: "Domain Controller",
				Description:      "KDC / Domain Controller IP or hostname",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: true, GroupName: "Default"},
				},
			},
			{
				Name:             "username",
				CLIName:          "username",
				ModalDisplayName: "Username",
				Description:      "Domain user for LDAP authentication (UPN format: user@domain.local)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: true, GroupName: "Default"},
				},
			},
			{
				Name:             "password",
				CLIName:          "password",
				ModalDisplayName: "Password",
				Description:      "Domain user password for LDAP authentication",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: true, GroupName: "Default"},
				},
			},
			{
				Name:             "realm",
				CLIName:          "realm",
				ModalDisplayName: "Realm",
				Description:      "Kerberos realm (auto-detected from username UPN if empty)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "account",
				CLIName:          "account",
				ModalDisplayName: "Target Account",
				Description:      "Specific account to roast (if empty, auto-enumerates all AS-REP roastable accounts via LDAP)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "port",
				CLIName:          "port",
				ModalDisplayName: "LDAP Port",
				Description:      "LDAP port for account enumeration (default: 389)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				DefaultValue:     389,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "base_dn",
				CLIName:          "base_dn",
				ModalDisplayName: "Base DN",
				Description:      "LDAP search base for account enumeration (auto-detected if empty)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "use_tls",
				CLIName:          "use_tls",
				ModalDisplayName: "Use LDAPS",
				Description:      "Use TLS/LDAPS for account enumeration",
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

			server, _ := taskData.Args.GetStringArg("server")
			account, _ := taskData.Args.GetStringArg("account")

			displayMsg := fmt.Sprintf("AS-REP Roast %s", server)
			if account != "" {
				displayMsg += fmt.Sprintf(" account=%s", account)
			} else {
				displayMsg += " (auto-enumerate targets)"
			}
			response.DisplayParams = &displayMsg

			mythicrpc.SendMythicRPCArtifactCreate(mythicrpc.MythicRPCArtifactCreateMessage{
				TaskID:           taskData.Task.ID,
				BaseArtifactType: "API Call",
				ArtifactMessage:  fmt.Sprintf("Kerberos AS-REQ to KDC %s (no pre-auth)", server),
			})

			return response
		},
	})
}
