package agentfunctions

import (
	"fmt"
	"strings"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
	"github.com/MythicMeta/MythicContainer/mythicrpc"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "gpp-password",
		Description:         "Extract Group Policy Preferences passwords from SYSVOL via SMB (T1552.006)",
		HelpString:          "gpp-password -server <DC> -username <user@domain> -password <pass>",
		Version:             1,
		SupportedUIFeatures: []string{},
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1552.006"},
		ScriptOnlyCommand:   false,
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_LINUX, agentstructs.SUPPORTED_OS_MACOS, agentstructs.SUPPORTED_OS_WINDOWS},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:             "server",
				ModalDisplayName: "Domain Controller",
				CLIName:          "server",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Domain controller hostname or IP",
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: true,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "username",
				ModalDisplayName: "Username",
				CLIName:          "username",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Username (user@domain or DOMAIN\\user)",
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: true,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "password",
				ModalDisplayName: "Password",
				CLIName:          "password",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Password for authentication",
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: true,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "domain",
				ModalDisplayName: "Domain",
				CLIName:          "domain",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Domain name (optional if included in username)",
				DefaultValue:     "",
				DynamicQueryFunction: getCallbackDomainList,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "port",
				ModalDisplayName: "SMB Port",
				CLIName:          "port",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				Description:      "SMB port (default: 445)",
				DefaultValue:     445,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
		},
		AssociatedBrowserScript: nil,
		TaskFunctionOPSECPre: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTTaskOPSECPreTaskMessageResponse {
				server, _ := taskData.Args.GetStringArg("server")
				return agentstructs.PTTTaskOPSECPreTaskMessageResponse{
					TaskID:             taskData.Task.ID,
					Success:            true,
					OpsecPreBlocked:    false,
					OpsecPreMessage:    fmt.Sprintf("OPSEC WARNING: GPP password extraction from %s. Accesses SYSVOL share to search for Group Policy Preferences XML files containing encrypted credentials (cpassword). Generates SMB share access events (Event ID 5140) to SYSVOL.", server),
					OpsecPreBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
				}
			},
		TaskFunctionOPSECPost: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskOPSECPostTaskMessageResponse {
			return agentstructs.PTTaskOPSECPostTaskMessageResponse{
				TaskID:              taskData.Task.ID,
				Success:             true,
				OpsecPostBlocked:    false,
				OpsecPostMessage:    "OPSEC AUDIT: Group Policy Preferences password extracted. SYSVOL access is logged in SMB audit events. The cpassword field uses a known AES key — GPP passwords are trivially decrypted. This is a well-known attack vector that defenders monitor.",
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
		TaskFunctionCreateTasking: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  taskData.Task.ID,
			}
			server, _ := taskData.Args.GetStringArg("server")
			display := fmt.Sprintf("SYSVOL on %s", server)
			response.DisplayParams = &display
			createArtifact(taskData.Task.ID, "File Read", fmt.Sprintf("GPP Groups.xml password extraction from \\\\%s\\SYSVOL", server))
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
			var creds []mythicrpc.MythicRPCCredentialCreateCredentialData
			// Parse GPP output blocks: --- Credential N ---\n  Username: ...\n  Password: ...\n  File: ...
			blocks := strings.Split(responseText, "--- Credential ")
			for _, block := range blocks {
				if block == "" {
					continue
				}
				lines := strings.Split(block, "\n")
				var username, password, file string
				for _, line := range lines {
					trimmed := strings.TrimSpace(line)
					if strings.HasPrefix(trimmed, "Username:") {
						username = strings.TrimSpace(strings.TrimPrefix(trimmed, "Username:"))
					} else if strings.HasPrefix(trimmed, "Password:") {
						password = strings.TrimSpace(strings.TrimPrefix(trimmed, "Password:"))
					} else if strings.HasPrefix(trimmed, "File:") {
						file = strings.TrimSpace(strings.TrimPrefix(trimmed, "File:"))
					}
				}
				if username != "" && password != "" {
					creds = append(creds, mythicrpc.MythicRPCCredentialCreateCredentialData{
						CredentialType: "plaintext",
						Realm:          processResponse.TaskData.Callback.Host,
						Account:        username,
						Credential:     password,
						Comment:        fmt.Sprintf("gpp-password (%s)", file),
					})
				}
			}
			registerCredentials(processResponse.TaskData.Task.ID, creds)
			return response
		},
	})
}
