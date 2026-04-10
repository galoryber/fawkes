package agentfunctions

import (
	"path/filepath"
	"strings"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name: "debug-detect",
		AssociatedBrowserScript: &agentstructs.BrowserScript{
			ScriptPath: filepath.Join(".", "fawkes", "browserscripts", "debugdetect_new.js"),
			Author:     "@GlobeTech",
		},
		Description:         "Detect attached debuggers, analysis tools, and instrumentation. Windows: IsDebuggerPresent, NtQueryInformationProcess, PEB, DR registers. Linux: TracerPid, LD_PRELOAD, memory maps (Frida/Valgrind/sanitizers), process status, VM/sandbox detection. macOS: P_TRACED, DYLD_INSERT_LIBRARIES, VM detection (sysctl), security products (EDR/AV LaunchDaemons), sandbox/analysis environment. All: known debugger process scan.",
		HelpString:          "debug-detect",
		Version:             3,
		MitreAttackMappings: []string{"T1497.001"}, // Virtualization/Sandbox Evasion: System Checks
		SupportedUIFeatures: []string{},
		Author:              "@galoryber",
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_LINUX, agentstructs.SUPPORTED_OS_MACOS, agentstructs.SUPPORTED_OS_WINDOWS},
		},
		TaskFunctionParseArgString: func(args *agentstructs.PTTaskMessageArgsData, input string) error {
			return nil
		},
		TaskFunctionParseArgDictionary: func(args *agentstructs.PTTaskMessageArgsData, input map[string]interface{}) error {
			return nil
		},
		TaskFunctionOPSECPre: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTTaskOPSECPreTaskMessageResponse {
			return agentstructs.PTTTaskOPSECPreTaskMessageResponse{
				TaskID: taskData.Task.ID, Success: true,
				OpsecPreBlocked: false,
				OpsecPreMessage:    "OPSEC WARNING: Detects attached debuggers and analysis tools (T1497.001). Anti-debug checks (IsDebuggerPresent, TracerPid, timing) are a well-known malware indicator that sandboxes and EDR specifically watch for.",
				OpsecPreBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionOPSECPost: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskOPSECPostTaskMessageResponse {
			return agentstructs.PTTaskOPSECPostTaskMessageResponse{
				TaskID:              taskData.Task.ID,
				Success:             true,
				OpsecPostBlocked:    false,
				OpsecPostMessage:    "OPSEC AUDIT: Debugger detection completed. Anti-debug checks (IsDebuggerPresent, NtQueryInformationProcess, timing checks) are well-known malware behaviors. Sandboxes and EDR may flag these API calls. If a debugger was detected, consider terminating or altering behavior.",
				OpsecPostBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionCreateTasking: func(task *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			return agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  task.Task.ID,
			}
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
			if strings.Contains(responseText, "true") || strings.Contains(responseText, "detected") {
				tagTask(processResponse.TaskData.Task.ID, "OPSEC",
					"Debugger/analysis tool detected (T1497.001)")
			}
			logOperationEvent(processResponse.TaskData.Task.ID,
				"[RECON] Debug/analysis environment check (T1497.001)", false)
			return response
		},
	})
}
