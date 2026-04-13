package agentfunctions

import (
	"fmt"
	"path/filepath"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "jxa",
		Description:         "Execute JavaScript for Automation (JXA) scripts. JXA provides access to macOS automation APIs (Foundation, AppKit, Security) via JavaScript — useful for app enumeration, file operations, keychain queries, and system automation.",
		HelpString:          "jxa -code 'Application(\"System Events\").processes().name()'\njxa -file /tmp/script.js\njxa -code '...' -timeout 120",
		Version:             1,
		SupportedUIFeatures: []string{},
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1059.007"}, // Command and Scripting Interpreter: JavaScript
		ScriptOnlyCommand:   false,
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_MACOS},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:             "code",
				ModalDisplayName: "Inline Script",
				CLIName:          "code",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Inline JXA code to execute",
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
						UIModalPosition:     0,
					},
				},
			},
			{
				Name:             "file",
				ModalDisplayName: "Script File Path",
				CLIName:          "file",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Path to a .js file on the target to execute",
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
						UIModalPosition:     1,
					},
				},
			},
			{
				Name:             "timeout",
				ModalDisplayName: "Timeout (seconds)",
				CLIName:          "timeout",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				Description:      "Execution timeout in seconds (default: 60)",
				DefaultValue:     60,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
						UIModalPosition:     2,
					},
				},
			},
		},
		AssociatedBrowserScript: &agentstructs.BrowserScript{ScriptPath: filepath.Join(".", "fawkes", "browserscripts", "jxa_new.js"), Author: "@galoryber"},
		TaskFunctionOPSECPost: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskOPSECPostTaskMessageResponse {
			return agentstructs.PTTaskOPSECPostTaskMessageResponse{
				TaskID:              taskData.Task.ID,
				Success:             true,
				OpsecPostBlocked:    false,
				OpsecPostMessage:    "OPSEC AUDIT: JXA execution completed. osascript/JavaScript automation generates process creation events and may trigger macOS TCC prompts. Keychain access, file operations, and app interactions are logged by Unified Logging.",
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
		TaskFunctionOPSECPre: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTTaskOPSECPreTaskMessageResponse {
			return agentstructs.PTTTaskOPSECPreTaskMessageResponse{
				TaskID:             taskData.Task.ID,
				Success:            true,
				OpsecPreBlocked:    false,
				OpsecPreMessage:    "OPSEC WARNING: JXA (JavaScript for Automation) execution uses OSAScript APIs. macOS Endpoint Security framework logs script execution events. TCC prompts may appear if accessing protected resources (contacts, calendar, photos).",
				OpsecPreBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionCreateTasking: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  taskData.Task.ID,
			}
			code, _ := taskData.Args.GetStringArg("code")
			file, _ := taskData.Args.GetStringArg("file")
			var display string
			if code != "" {
				if len(code) > 80 {
					display = fmt.Sprintf("code: %s...", code[:80])
				} else {
					display = fmt.Sprintf("code: %s", code)
				}
			} else if file != "" {
				display = fmt.Sprintf("file: %s", file)
			}
			response.DisplayParams = &display
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
			logOperationEvent(processResponse.TaskData.Task.ID,
				fmt.Sprintf("[EXECUTION] JXA script executed (%d bytes output, T1059.007)", len(responseText)), false)
			return response
		},
	})
}
