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
		HelpString:          "vanilla-injection -action inject -pid 1234 -filename shellcode.bin\nvanilla-injection -action migrate -pid 1234 -filename fawkes-shellcode.bin\nvanilla-injection -action ldpreload -target /usr/bin/id -filename shellcode.bin (Linux, no ptrace)",
		Version:             3,
		MitreAttackMappings: []string{"T1055.001", "T1055.002", "T1055.009", "T1574.006"}, // DLL Injection, PE Injection, Proc Memory, LD_PRELOAD
		SupportedUIFeatures: []string{"process_browser:inject"},
		Author:              "@galoryber",
		AssociatedBrowserScript: &agentstructs.BrowserScript{ScriptPath: filepath.Join(".", "fawkes", "browserscripts", "vanillainjection_new.js"), Author: "@galoryber"},
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_WINDOWS, agentstructs.SUPPORTED_OS_LINUX},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:             "action",
				ModalDisplayName: "Action",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Description:      "inject: ptrace + /proc/mem injection. migrate: inject + exit current process. ldpreload: Linux-only, spawn process with LD_PRELOAD .so (no ptrace, bypasses Yama)",
				Choices:          []string{"inject", "migrate", "ldpreload"},
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
					{
						ParameterIsRequired: true,
						GroupName:           "CLI",
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
						UIModalPosition:     1,
					},
				},
			},
			{
				Name:                 "pid",
				ModalDisplayName:     "Target PID",
				CLIName:              "pid",
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
					{
						ParameterIsRequired: true,
						GroupName:           "CLI",
						UIModalPosition:     2,
					},
				},
			},
			{
				Name:             "target",
				ModalDisplayName: "Target Selection",
				CLIName:          "target",
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
					{
						ParameterIsRequired: false,
						GroupName:           "CLI",
						UIModalPosition:     4,
					},
				},
			},
			{
				Name:             "stack_spoof",
				ModalDisplayName: "Stack Spoof",
				CLIName:          "stack_spoof",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_BOOLEAN,
				Description:      "Spoof the call stack during injection API calls. Requires indirect_syscalls and stack_spoof build options.",
				DefaultValue:     false,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default", UIModalPosition: 5},
					{ParameterIsRequired: false, GroupName: "New File", UIModalPosition: 5},
					{ParameterIsRequired: false, GroupName: "CLI", UIModalPosition: 5},
				},
			},
		},
		TaskFunctionOPSECPre: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTTaskOPSECPreTaskMessageResponse {
			pid, _ := taskData.Args.GetStringArg("pid")
			action, _ := taskData.Args.GetStringArg("action")
			os := taskData.Callback.OS
			var msg string
			if strings.EqualFold(action, "ldpreload") {
				target, _ := taskData.Args.GetStringArg("target")
				if target == "" {
					target = "/usr/bin/id"
				}
				msg = fmt.Sprintf("OPSEC WARNING: LD_PRELOAD injection spawning %s. "+
					"Builds minimal ELF .so with DT_INIT pointing to shellcode, written "+
					"to anonymous memfd. No ptrace used — bypasses Yama ptrace_scope. "+
					"Artifacts: /proc/PID/maps shows (deleted) memfd entry.", target)
			} else if strings.EqualFold(os, "linux") {
				msg = fmt.Sprintf("OPSEC WARNING: /proc/PID/mem injection into PID %s. "+
					"Uses ptrace attach + /proc/mem direct write — avoids PTRACE_POKETEXT "+
					"but still requires ptrace capability. Yama LSM and seccomp may block.", pid)
			} else {
				msg = fmt.Sprintf("OPSEC WARNING: Classic process injection into PID %s. "+
					"Uses VirtualAllocEx + WriteProcessMemory + CreateRemoteThread — "+
					"the most detectable injection pattern. Most EDR products hook these APIs. "+
					"Consider threadless-inject or module-stomping for lower detection risk.", pid)
			}
			if action == "migrate" {
				msg += fmt.Sprintf("\n\nMIGRATION WARNING: This will inject a new agent instance into PID %s "+
					"and terminate the current agent process. The current callback will go offline. "+
					"A new callback will appear from the target process.", pid)
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
			os := taskData.Callback.OS
			var msg string
			if strings.EqualFold(os, "linux") {
				msg = fmt.Sprintf("OPSEC AUDIT: /proc/mem injection queued for PID %s. Artifact registered.", pid)
			} else {
				msg = fmt.Sprintf("OPSEC AUDIT: Classic injection (VirtualAllocEx+WriteProcessMemory+CreateRemoteThread) queued for PID %s. Artifact registered.", pid)
			}
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

			// Decode to get size for display
			scBytes, _ := base64.StdEncoding.DecodeString(shellcodeB64)

			// Get target selection mode (if any)
			target, _ := taskData.Args.GetStringArg("target")

			// Get the target PID (may be 0 if using auto-selection)
			pid, err := parsePIDFromArg(taskData)
			if err != nil {
				pid = 0
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
				displayParams = fmt.Sprintf("Action: %s\nShellcode: %s (%d bytes)\nTarget: %s (auto-select)", actionLabel, filename, len(scBytes), target)
			} else {
				displayParams = fmt.Sprintf("Action: %s\nShellcode: %s (%d bytes)\nTarget PID: %d", actionLabel, filename, len(scBytes), pid)
			}
			response.DisplayParams = &displayParams

			artifactDesc := fmt.Sprintf("VirtualAllocEx/WriteProcessMemory/CreateRemoteThread into PID %d (%d bytes)", pid, len(scBytes))
			if target != "" {
				artifactDesc = fmt.Sprintf("VirtualAllocEx/WriteProcessMemory/CreateRemoteThread with auto-target '%s' (%d bytes)", target, len(scBytes))
			}
			if action == "migrate" {
				artifactDesc += " [MIGRATE: agent will self-terminate after injection]"
			}
			createArtifact(taskData.Task.ID, "Process Inject", artifactDesc)

			stackSpoof, _ := taskData.Args.GetBooleanArg("stack_spoof")
			params := map[string]interface{}{
				"shellcode_b64": shellcodeB64,
				"pid":           pid,
				"target":        target,
				"action":        action,
				"stack_spoof":   stackSpoof,
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
