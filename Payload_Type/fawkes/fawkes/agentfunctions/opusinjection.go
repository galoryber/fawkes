package agentfunctions

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"path/filepath"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
	"github.com/MythicMeta/MythicContainer/logging"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "opus-injection",
		Description:         "Perform novel callback-based process injection using unexplored Windows mechanisms. Named after Claude Opus who researched these techniques.",
		HelpString:          "opus-injection",
		Version:             1,
		MitreAttackMappings: []string{"T1055"}, // Process Injection
		SupportedUIFeatures: []string{"process_browser:inject"},
		Author:              "@galoryber",
		AssociatedBrowserScript: &agentstructs.BrowserScript{ScriptPath: filepath.Join(".", "fawkes", "browserscripts", "opusinjection_new.js"), Author: "@galoryber"},
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_WINDOWS},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:             "variant",
				ModalDisplayName: "Injection Variant",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Description:      "The Opus injection variant to use",
				Choices: []string{
					"1 - Ctrl-C Handler Chain (console processes)",
					"4 - KernelCallbackTable (GUI processes)",
				},
				DefaultValue: "1 - Ctrl-C Handler Chain (console processes)",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: true,
						GroupName:           "Default",
						UIModalPosition:     1,
					},
					{
						ParameterIsRequired: true,
						GroupName:           "New File",
						UIModalPosition:     1,
					},
				},
			},
			{
				Name:                 "filename",
				ModalDisplayName:     "Shellcode File",
				ParameterType:        agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Description:          "The shellcode file to inject from files already registered in Mythic",
				Choices:              []string{},
				DefaultValue:         "",
				DynamicQueryFunction: getFileList,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: true,
						GroupName:           "Default",
						UIModalPosition:     0,
					},
				},
			},
			{
				Name:             "file",
				ModalDisplayName: "Shellcode File",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_FILE,
				Description:      "Upload a new shellcode file to inject",
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: true,
						GroupName:           "New File",
						UIModalPosition:     0,
					},
				},
			},
			{
				Name:             "pid",
				ModalDisplayName: "Target PID",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				Description:      "The process ID to inject into (console process for Variant 1, GUI process for Variant 4)",
				DefaultValue:     0,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: true,
						GroupName:           "Default",
						UIModalPosition:     2,
					},
					{
						ParameterIsRequired: true,
						GroupName:           "New File",
						UIModalPosition:     2,
					},
				},
			},
		},
		TaskFunctionOPSECPre: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTTaskOPSECPreTaskMessageResponse {
			pid, _ := taskData.Args.GetNumberArg("pid")
			variant, _ := taskData.Args.GetStringArg("variant")
			return agentstructs.PTTTaskOPSECPreTaskMessageResponse{
				TaskID:             taskData.Task.ID,
				Success:            true,
				OpsecPreBlocked:    false,
				OpsecPreMessage:    fmt.Sprintf("OPSEC WARNING: Opus injection (variant: %s) into PID %d. Callback-based injection using unexplored Windows mechanisms — novel technique with minimal EDR signatures.", variant, int(pid)),
				OpsecPreBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionOPSECPost: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskOPSECPostTaskMessageResponse {
			pid, _ := taskData.Args.GetNumberArg("pid")
			variant, _ := taskData.Args.GetStringArg("variant")
			return agentstructs.PTTaskOPSECPostTaskMessageResponse{
				TaskID:              taskData.Task.ID,
				Success:             true,
				OpsecPostBlocked:    false,
				OpsecPostMessage:    fmt.Sprintf("OPSEC AUDIT: Opus injection (variant: %s) queued for PID %d. Artifact registered.", variant, int(pid)),
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

			// Get the variant selection
			variantStr, err := taskData.Args.GetStringArg("variant")
			if err != nil {
				logging.LogError(err, "Failed to get variant")
				response.Success = false
				response.Error = "Failed to get injection variant: " + err.Error()
				return response
			}

			// Parse variant number from string like "1 - Ctrl-C Handler..."
			var variant int
			if len(variantStr) > 0 {
				fmt.Sscanf(variantStr, "%d", &variant)
			}

			if variant != 1 && variant != 4 {
				response.Success = false
				response.Error = fmt.Sprintf("Invalid variant: %d. Currently supported: 1, 4", variant)
				return response
			}

			// Resolve file contents by checking actual args (not ParameterGroupName)
			filename, fileContents, fErr := resolveFileContents(taskData)
			if fErr != nil {
				response.Success = false
				response.Error = fErr.Error()
				return response
			}

			// Get the target PID
			pid, err := taskData.Args.GetNumberArg("pid")
			if err != nil {
				logging.LogError(err, "Failed to get PID")
				response.Success = false
				response.Error = "Failed to get target PID: " + err.Error()
				return response
			}

			if pid <= 0 {
				response.Success = false
				response.Error = "Invalid PID specified (must be greater than 0)"
				return response
			}

			// Build variant description
			variantDesc := "Unknown"
			targetNote := ""
			switch variant {
			case 1:
				variantDesc = "Ctrl-C Handler Chain Injection"
				targetNote = "Target must be a console process"
			case 4:
				variantDesc = "PEB KernelCallbackTable Injection"
				targetNote = "Target must be a GUI process with user32.dll loaded"
			}

			// Build the display parameters
			displayParams := fmt.Sprintf("Variant: %d (%s)\nShellcode: %s (%d bytes)\nTarget PID: %d\nNote: %s",
				variant, variantDesc, filename, len(fileContents), int(pid), targetNote)
			response.DisplayParams = &displayParams
			createArtifact(taskData.Task.ID, "Process Inject", fmt.Sprintf("Opus variant %d (%s) into PID %d (%d bytes)", variant, variantDesc, int(pid), len(fileContents)))

			// Build the actual parameters JSON that will be sent to the agent
			params := map[string]interface{}{
				"shellcode_b64": base64.StdEncoding.EncodeToString(fileContents),
				"pid":           int(pid),
				"variant":       variant,
			}

			paramsJSON, err := json.Marshal(params)
			if err != nil {
				logging.LogError(err, "Failed to marshal parameters")
				response.Success = false
				response.Error = "Failed to create task parameters: " + err.Error()
				return response
			}

			taskData.Args.SetManualArgs(string(paramsJSON))

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
			if strings.Contains(responseText, "success") || strings.Contains(responseText, "injected") || strings.Contains(responseText, "Success") || strings.Contains(responseText, "Injected") {
				l := len(responseText)
				if l > 200 {
					l = 200
				}
				createArtifact(processResponse.TaskData.Task.ID, "Process Injection", fmt.Sprintf("[opus-injection] %s", responseText[:l]))
			}
			return response
		},
	})
}
