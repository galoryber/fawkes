package agentfunctions

import (
	"encoding/json"
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
				Name:                "server",
				CLIName:             "server",
				ModalDisplayName:    "Domain Controller",
				Description:         "KDC / Domain Controller IP or hostname",
				ParameterType:       agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:        "",
				DynamicQueryFunction: getActiveHostList,
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
				DynamicQueryFunction: getCallbackUserList,
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
			if input == "" {
				return nil
			}
			return args.LoadArgsFromJSONString(input)
		},
		TaskFunctionParseArgDictionary: func(args *agentstructs.PTTaskMessageArgsData, input map[string]interface{}) error {
			return args.LoadArgsFromDictionary(input)
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
			var entries []struct {
				Account string `json:"account"`
				Etype   string `json:"etype"`
				Hash    string `json:"hash"`
				Status  string `json:"status"`
			}
			if err := json.Unmarshal([]byte(responseText), &entries); err != nil {
				return response
			}
			var creds []mythicrpc.MythicRPCCredentialCreateCredentialData
			realm := processResponse.TaskData.Callback.Host
			for _, e := range entries {
				if e.Status != "roasted" || e.Hash == "" {
					continue
				}
				creds = append(creds, mythicrpc.MythicRPCCredentialCreateCredentialData{
					CredentialType: "hash",
					Realm:          realm,
					Account:        e.Account,
					Credential:     e.Hash,
					Comment:        fmt.Sprintf("asrep-roast (%s)", e.Etype),
				})
			}
			registerCredentials(processResponse.TaskData.Task.ID, creds)
			if len(creds) > 0 {
				logOperationEvent(processResponse.TaskData.Task.ID,
					fmt.Sprintf("[CREDENTIAL] asrep-roast extracted %d AS-REP hashes from %s", len(creds), realm), true)
			}
			return response
		},
		TaskFunctionOPSECPre: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTTaskOPSECPreTaskMessageResponse {
			return agentstructs.PTTTaskOPSECPreTaskMessageResponse{
				TaskID:             taskData.Task.ID,
				Success:            true,
				OpsecPreBlocked:    false,
				OpsecPreMessage:    "OPSEC WARNING: AS-REP Roasting queries accounts without Kerberos pre-authentication. Generates LDAP queries for userAccountControl flags and AS-REQ/AS-REP traffic. Event ID 4768 with pre-auth type 0 is detectable. Less commonly monitored than Kerberoasting but increasingly flagged.",
				OpsecPreBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
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

			createArtifact(taskData.Task.ID, "Network Connection", fmt.Sprintf("AS-REP roast request to %s", server))

			return response
		},
	})
}
