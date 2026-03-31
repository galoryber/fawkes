package agentfunctions

import (
	"path/filepath"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name: "proxy-check",
		AssociatedBrowserScript: &agentstructs.BrowserScript{
			ScriptPath: filepath.Join(".", "fawkes", "browserscripts", "proxycheck_new.js"),
			Author:     "@galoryber",
		},
		Description:         "Detect system proxy settings from environment variables, OS configuration, and registry (Windows). Optionally test proxy connectivity.",
		HelpString:          "proxy-check\nproxy-check -test_url http://example.com",
		Version:             1,
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1016"},
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{
				agentstructs.SUPPORTED_OS_WINDOWS,
				agentstructs.SUPPORTED_OS_LINUX,
				agentstructs.SUPPORTED_OS_MACOS,
			},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:          "test_url",
				CLIName:       "test_url",
				Description:   "Optional URL to test proxy connectivity",
				DefaultValue:  "",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
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
			return agentstructs.PTTTaskOPSECPreTaskMessageResponse{
				TaskID:             taskData.Task.ID,
				Success:            true,
				OpsecPreBlocked:    false,
				OpsecPreMessage:    "OPSEC WARNING: Proxy detection reads system proxy configuration (registry on Windows, env vars on Linux/macOS). Enumerates network egress controls — useful for C2 routing but may be logged.",
				OpsecPreBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionCreateTasking: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{Success: true, TaskID: taskData.Task.ID}
			testURL, _ := taskData.Args.GetStringArg("test_url")
			if testURL != "" {
				dp := testURL
				response.DisplayParams = &dp
			}
			return response
		},
	})
}
