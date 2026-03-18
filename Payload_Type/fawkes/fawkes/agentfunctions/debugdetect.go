package agentfunctions

import (
	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "debug-detect",
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
		TaskFunctionCreateTasking: func(task *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			return agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  task.Task.ID,
			}
		},
	})
}
