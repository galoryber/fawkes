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
		Name:                "apc-injection",
		Description:         "Remote process injection via QueueUserAPC (default, requires alertable thread) or HWBP (DebugActiveProcess + DR0, no TID required).",
		HelpString:          "apc-injection",
		Version:             1,
		MitreAttackMappings: []string{"T1055.004", "T1055"}, // Process Injection: APC + generic process injection (HWBP)
		SupportedUIFeatures: []string{"process_browser:inject"},
		Author:              "@galoryber",
		AssociatedBrowserScript: &agentstructs.BrowserScript{ScriptPath: filepath.Join(".", "fawkes", "browserscripts", "apcinjection_new.js"), Author: "@galoryber"},
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_WINDOWS},
			FilterCommandAvailabilityByAgentBuildParameters: map[string]string{"selected_os": "Windows"},
		},
		CommandParameters: []agentstructs.CommandParameter{
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
				ParameterType:        agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:          "The process ID containing the target thread",
				DynamicQueryFunction: getProcessList,
				DefaultValue:         "",
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
				Name:             "tid",
				ModalDisplayName: "Target Thread ID (APC method only)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				Description:      "Thread ID to queue the APC to (use 'ts' command to find alertable threads). Only required when method=apc.",
				DefaultValue:     0,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default", UIModalPosition: 2},
					{ParameterIsRequired: false, GroupName: "New File", UIModalPosition: 2},
					{ParameterIsRequired: false, GroupName: "CLI", UIModalPosition: 2},
				},
			},
			{
				Name:             "method",
				ModalDisplayName: "Injection Method",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Description:      "apc = QueueUserAPC into alertable thread (default). hwbp = DebugActiveProcess + DR0 hardware breakpoint redirect (no TID required, attaches as debugger briefly).",
				DefaultValue:     "apc",
				Choices:          []string{"apc", "hwbp"},
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default", UIModalPosition: 3},
					{ParameterIsRequired: false, GroupName: "New File", UIModalPosition: 3},
					{ParameterIsRequired: false, GroupName: "CLI", UIModalPosition: 3},
				},
			},
			{
				Name:             "target_api",
				ModalDisplayName: "HWBP Breakpoint API",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Function to set DR0 breakpoint on (HWBP method only). Format: module!function. Default: ntdll!NtDelayExecution. Module must be a KnownDll for the address to be valid in the target.",
				DefaultValue:     "ntdll!NtDelayExecution",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default", UIModalPosition: 4},
					{ParameterIsRequired: false, GroupName: "New File", UIModalPosition: 4},
					{ParameterIsRequired: false, GroupName: "CLI", UIModalPosition: 4},
				},
			},
			{
				Name:             "timeout_ms",
				ModalDisplayName: "HWBP Timeout (ms)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				Description:      "Maximum time to wait for the breakpoint to fire (HWBP method only). Default 30000 (30s).",
				DefaultValue:     30000,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default", UIModalPosition: 5},
					{ParameterIsRequired: false, GroupName: "New File", UIModalPosition: 5},
					{ParameterIsRequired: false, GroupName: "CLI", UIModalPosition: 5},
				},
			},
			{
				Name:             "hwbp_debug",
				ModalDisplayName: "HWBP Verbose Trace",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_BOOLEAN,
				Description:      "Enable verbose per-event tracing and DR0/DR7 readback verification (HWBP method only). Output can be substantial — first 60 events full detail + per-exception-code summary. Use to diagnose why a breakpoint never fires.",
				DefaultValue:     false,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default", UIModalPosition: 7},
					{ParameterIsRequired: false, GroupName: "New File", UIModalPosition: 7},
					{ParameterIsRequired: false, GroupName: "CLI", UIModalPosition: 7},
				},
			},
			{
				Name:             "target",
				ModalDisplayName: "Target Selection",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Description:      "Auto-select injection target (EDR-aware scoring). PID still required for thread selection.",
				DefaultValue:     "",
				Choices:          []string{"", "auto", "auto-elevated", "auto-user"},
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
						UIModalPosition:     6,
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
					{ParameterIsRequired: false, GroupName: "Default", UIModalPosition: 8},
					{ParameterIsRequired: false, GroupName: "New File", UIModalPosition: 8},
					{ParameterIsRequired: false, GroupName: "CLI", UIModalPosition: 8},
				},
			},
		},
		TaskFunctionOPSECPre: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTTaskOPSECPreTaskMessageResponse {
			pid, _ := taskData.Args.GetStringArg("pid")
			method, _ := taskData.Args.GetStringArg("method")
			if method == "" {
				method = "apc"
			}
			var msg string
			switch method {
			case "hwbp":
				targetAPI, _ := taskData.Args.GetStringArg("target_api")
				if targetAPI == "" {
					targetAPI = "ntdll!NtDelayExecution"
				}
				msg = fmt.Sprintf("OPSEC WARNING: HWBP injection into PID %s via DebugActiveProcess + DR0 on %s. "+
					"Attaches as debugger to the target — Sysmon EID 10 (ProcessAccess with DEBUG_PROCESS rights), "+
					"SetThreadContext into another process, and the cross-process VirtualAllocEx + WriteProcessMemory "+
					"are all high-fidelity detections. Target receives no thread injection event but does receive a "+
					"debug-attach event. Avoid against PPL / protected processes — DebugActiveProcess will fail.", pid, targetAPI)
			default:
				msg = fmt.Sprintf("OPSEC WARNING: APC injection into PID %s. "+
					"Queues shellcode via NtQueueApcThread — requires alertable thread in target. "+
					"Less common than CreateRemoteThread but still monitored by advanced EDR.", pid)
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
			method, _ := taskData.Args.GetStringArg("method")
			if method == "" {
				method = "apc"
			}
			var msg string
			if method == "hwbp" {
				msg = fmt.Sprintf("OPSEC AUDIT: HWBP injection completed against PID %s. Debugger attach + detach recorded. Artifact registered.", pid)
			} else {
				tid, _ := taskData.Args.GetNumberArg("tid")
				msg = fmt.Sprintf("OPSEC AUDIT: APC injection queued for PID %s TID %d. Artifact registered.", pid, int(tid))
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

			// Check for CLI group (shellcode_b64 provided directly)
			var shellcodeB64 string
			var filename string

			scB64, _ := taskData.Args.GetStringArg("shellcode_b64")
			if scB64 != "" {
				shellcodeB64 = scB64
				filename = "cli-shellcode"
			} else {
				var fileContents []byte
				var err error
				filename, fileContents, err = resolveFileContents(taskData)
				if err != nil {
					response.Success = false
					response.Error = err.Error()
					return response
				}
				shellcodeB64 = base64.StdEncoding.EncodeToString(fileContents)
			}

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

			method, _ := taskData.Args.GetStringArg("method")
			if method == "" {
				method = "apc"
			}

			stackSpoof, _ := taskData.Args.GetBooleanArg("stack_spoof")
			params := map[string]interface{}{
				"shellcode_b64": shellcodeB64,
				"pid":           pid,
				"method":        method,
				"stack_spoof":   stackSpoof,
			}
			var displayParams string

			switch method {
			case "hwbp":
				targetAPI, _ := taskData.Args.GetStringArg("target_api")
				if targetAPI == "" {
					targetAPI = "ntdll!NtDelayExecution"
				}
				timeoutMs, _ := taskData.Args.GetNumberArg("timeout_ms")
				if timeoutMs <= 0 {
					timeoutMs = 30000
				}
				hwbpDebug, _ := taskData.Args.GetBooleanArg("hwbp_debug")
				params["target_api"] = targetAPI
				params["timeout_ms"] = int(timeoutMs)
				params["hwbp_debug"] = hwbpDebug
				debugSuffix := ""
				if hwbpDebug {
					debugSuffix = "\nVerbose Trace: enabled"
				}
				displayParams = fmt.Sprintf("Shellcode: %s\nTarget PID: %d\nMethod: hwbp\nBreakpoint API: %s\nTimeout: %dms%s",
					filename, pid, targetAPI, int(timeoutMs), debugSuffix)
				createArtifact(taskData.Task.ID, "Process Inject",
					fmt.Sprintf("HWBP injection into PID %d (DR0 = %s, %dms timeout)", pid, targetAPI, int(timeoutMs)))
			case "apc":
				tid, terr := taskData.Args.GetNumberArg("tid")
				if terr != nil {
					logging.LogError(terr, "Failed to get TID")
					response.Success = false
					response.Error = "Failed to get target Thread ID: " + terr.Error()
					return response
				}
				if tid <= 0 {
					response.Success = false
					response.Error = "APC method requires a valid Thread ID (use 'ts' to find alertable threads, or pick method=hwbp)"
					return response
				}
				params["tid"] = int(tid)
				displayParams = fmt.Sprintf("Shellcode: %s\nTarget PID: %d\nTarget TID: %d\nMethod: apc", filename, pid, int(tid))
				createArtifact(taskData.Task.ID, "Process Inject",
					fmt.Sprintf("APC injection into PID %d TID %d", pid, int(tid)))
			default:
				response.Success = false
				response.Error = fmt.Sprintf("Unknown injection method %q (expected \"apc\" or \"hwbp\")", method)
				return response
			}

			response.DisplayParams = &displayParams
			paramsJSON, err := json.Marshal(params)
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
			method, _ := processResponse.TaskData.Args.GetStringArg("method")
			if method == "" {
				method = "apc"
			}
			label := "APC injection"
			eventTag := "[EXECUTION] APC queue injection"
			if method == "hwbp" {
				label = "HWBP injection (DebugActiveProcess + DR0 redirect)"
				eventTag = "[EXECUTION] HWBP injection"
			}
			mythicrpc.SendMythicRPCArtifactCreate(mythicrpc.MythicRPCArtifactCreateMessage{
				TaskID:           processResponse.TaskData.Task.ID,
				BaseArtifactType: "Process Injection",
				ArtifactMessage:  fmt.Sprintf("%s on %s", label, host),
			})
			logOperationEvent(processResponse.TaskData.Task.ID,
				fmt.Sprintf("%s on %s", eventTag, host), true)
			return response
		},
	})
}
