package agentfunctions

import (
	"fmt"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
	"github.com/MythicMeta/MythicContainer/mythicrpc"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "ticket",
		Description:         "Forge Kerberos tickets (Golden Ticket / Silver Ticket) from extracted keys. Uses krbtgt key for TGTs (Golden) or service key for TGSs (Silver). Outputs kirbi (Rubeus) or ccache (Linux) format.",
		HelpString:          "ticket -action forge -realm CORP.LOCAL -username Administrator -domain_sid S-1-5-21-... -key <hex_aes256_key>\nticket -action forge -realm CORP.LOCAL -username Administrator -domain_sid S-1-5-21-... -key <hex_key> -key_type rc4 -format ccache\nticket -action forge -realm CORP.LOCAL -username sqlsvc -domain_sid S-1-5-21-... -key <hex_key> -spn MSSQLSvc/db01.corp.local:1433",
		Version:             1,
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1558.001", "T1558.002"},
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
				Description:      "Action to perform (forge)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
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
				Name:             "username",
				CLIName:          "username",
				ModalDisplayName: "Username",
				Description:      "Username for the forged ticket (e.g., Administrator)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: true, GroupName: "Default"},
				},
			},
			{
				Name:             "domain_sid",
				CLIName:          "domain_sid",
				ModalDisplayName: "Domain SID",
				Description:      "Domain SID (e.g., S-1-5-21-1234567890-1234567890-1234567890)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: true, GroupName: "Default"},
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
				Description:      "Service Principal Name for Silver Ticket (e.g., cifs/dc01.corp.local). Omit for Golden Ticket.",
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
		TaskFunctionCreateTasking: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  taskData.Task.ID,
			}

			realm, _ := taskData.Args.GetStringArg("realm")
			username, _ := taskData.Args.GetStringArg("username")
			spn, _ := taskData.Args.GetStringArg("spn")

			var ticketType string
			if spn == "" {
				ticketType = "Golden Ticket (TGT)"
			} else {
				ticketType = fmt.Sprintf("Silver Ticket (TGS: %s)", spn)
			}
			displayMsg := fmt.Sprintf("Forge %s for %s@%s", ticketType, username, realm)
			response.DisplayParams = &displayMsg

			mythicrpc.SendMythicRPCArtifactCreate(mythicrpc.MythicRPCArtifactCreateMessage{
				TaskID:           taskData.Task.ID,
				BaseArtifactType: "API Call",
				ArtifactMessage:  fmt.Sprintf("Forge Kerberos %s for %s@%s", ticketType, username, realm),
			})

			return response
		},
	})
}
