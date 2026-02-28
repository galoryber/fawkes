package agentfunctions

import (
	"fmt"
	"path/filepath"
	"strings"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "spray",
		Description:         "Password spray or Kerberos user enumeration against AD. Spray via Kerberos pre-auth, LDAP bind, or SMB auth. SMB supports pass-the-hash. Enumerate validates usernames without credentials.",
		HelpString:          "spray -action kerberos -server 192.168.1.1 -domain CORP.LOCAL -users \"user1\\nuser2\\nuser3\" -password Summer2026!\nspray -action smb -server dc01 -domain corp.local -users \"admin\\njsmith\" -hash aad3b435b51404ee:8846f7eaee8fb117\nspray -action enumerate -server dc01 -domain corp.local -users \"admin\\njsmith\\nsvc_backup\"\nspray -action ldap -server dc01 -domain corp.local -users \"admin\\njsmith\" -password Password1 -delay 1000 -jitter 25",
		Version:             2,
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1110.003", "T1550.002", "T1589.002"},
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{
				agentstructs.SUPPORTED_OS_WINDOWS,
				agentstructs.SUPPORTED_OS_LINUX,
				agentstructs.SUPPORTED_OS_MACOS,
			},
		},
		AssociatedBrowserScript: &agentstructs.BrowserScript{ScriptPath: filepath.Join(".", "fawkes", "browserscripts", "spray_new.js"), Author: "@galoryber"},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:             "action",
				CLIName:          "action",
				ModalDisplayName: "Protocol",
				Description:      "Action: kerberos (AS-REQ pre-auth), ldap (simple bind), smb (NTLM auth), enumerate (username validation without credentials)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:          []string{"kerberos", "ldap", "smb", "enumerate"},
				DefaultValue:     "kerberos",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: true, GroupName: "Default"},
				},
			},
			{
				Name:             "server",
				CLIName:          "server",
				ModalDisplayName: "Target Server",
				Description:      "Domain Controller or target server IP/hostname",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: true, GroupName: "Default"},
				},
			},
			{
				Name:             "domain",
				CLIName:          "domain",
				ModalDisplayName: "Domain",
				Description:      "Domain name (e.g., CORP.LOCAL)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: true, GroupName: "Default"},
				},
			},
			{
				Name:             "users",
				CLIName:          "users",
				ModalDisplayName: "Username List",
				Description:      "Newline-separated list of usernames to spray (e.g., user1\\nuser2\\nuser3)",
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
				Description:      "Password to spray (not required for enumerate action, or use -hash for SMB PTH)",
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
				Description:      "NT hash for SMB pass-the-hash spray (hex, e.g., aad3b435b51404ee:8846f7eaee8fb117 or just the NT hash)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "delay",
				CLIName:          "delay",
				ModalDisplayName: "Delay (ms)",
				Description:      "Delay between authentication attempts in milliseconds (default: 0)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				DefaultValue:     0,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "jitter",
				CLIName:          "jitter",
				ModalDisplayName: "Jitter (%)",
				Description:      "Jitter percentage for delay randomization (0-100, default: 0)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				DefaultValue:     0,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "port",
				CLIName:          "port",
				ModalDisplayName: "Port",
				Description:      "Custom port (default: 88 for Kerberos, 389/636 for LDAP, 445 for SMB)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				DefaultValue:     0,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "use_tls",
				CLIName:          "use_tls",
				ModalDisplayName: "Use TLS",
				Description:      "Use TLS/LDAPS for LDAP spray (default: false)",
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
		TaskFunctionCreateTasking: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  taskData.Task.ID,
			}

			action, _ := taskData.Args.GetStringArg("action")
			server, _ := taskData.Args.GetStringArg("server")
			domain, _ := taskData.Args.GetStringArg("domain")
			users, _ := taskData.Args.GetStringArg("users")

			// Count users
			userCount := 0
			for _, line := range strings.Split(users, "\n") {
				if strings.TrimSpace(line) != "" {
					userCount++
				}
			}

			var displayMsg string
			if action == "enumerate" {
				displayMsg = fmt.Sprintf("Enumerate users on %s (%s, %d users)", server, domain, userCount)
			} else {
				displayMsg = fmt.Sprintf("Spray %s via %s (%s, %d users)", server, action, domain, userCount)
			}
			response.DisplayParams = &displayMsg

			var artifactMsg string
			if action == "enumerate" {
				artifactMsg = fmt.Sprintf("Kerberos user enumeration against %s (%d users)", server, userCount)
			} else {
				artifactMsg = fmt.Sprintf("Password spray via %s against %s (%d users)", action, server, userCount)
			}
			createArtifact(taskData.Task.ID, "Network Connection", artifactMsg)

			return response
		},
	})
}
