package agentfunctions

import (
	"fmt"
	"strings"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "ntdll-unhook",
		Description:         "Remove EDR inline hooks from DLLs by restoring the .text section from a clean on-disk copy. Supports ntdll.dll, kernel32.dll, kernelbase.dll, advapi32.dll, or all at once.",
		HelpString:          "ntdll-unhook [-action unhook|check] [-dll ntdll.dll|kernel32.dll|kernelbase.dll|advapi32.dll|all]",
		Version:             1,
		SupportedUIFeatures: []string{},
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1562.001"},
		ScriptOnlyCommand:   false,
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_WINDOWS},
			FilterCommandAvailabilityByAgentBuildParameters: map[string]string{"selected_os": "Windows"},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:             "action",
				ModalDisplayName: "Action",
				CLIName:          "action",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:          []string{"unhook", "check"},
				Description:      "unhook: restore clean .text section from disk. check: compare in-memory vs disk and report hooks.",
				DefaultValue:     "unhook",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "dll",
				ModalDisplayName: "Target DLL",
				CLIName:          "dll",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:          []string{"ntdll.dll", "kernel32.dll", "kernelbase.dll", "advapi32.dll", "all"},
				Description:      "Which DLL to unhook/check. 'all' processes ntdll.dll, kernel32.dll, kernelbase.dll, and advapi32.dll.",
				DefaultValue:     "ntdll.dll",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
		},
		AssociatedBrowserScript: nil,
		TaskFunctionOPSECPre: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTTaskOPSECPreTaskMessageResponse {
			return agentstructs.PTTTaskOPSECPreTaskMessageResponse{
				TaskID:  taskData.Task.ID,
				Success: true,
				OpsecPreBlocked: false,
				OpsecPreMessage: "OPSEC WARNING: Unhooking ntdll.dll by remapping from disk. " +
					"This removes EDR/AV userland hooks but the act of reading ntdll.dll from disk " +
					"and remapping the .text section may itself be detected by kernel-level monitoring.",
				OpsecPreBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionOPSECPost: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskOPSECPostTaskMessageResponse {
			return agentstructs.PTTaskOPSECPostTaskMessageResponse{
				TaskID:              taskData.Task.ID,
				Success:             true,
				OpsecPostBlocked:    false,
				OpsecPostMessage:    "OPSEC AUDIT: NTDLL unhooking configured. Fresh ntdll.dll copy will be read from disk.",
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
			action, _ := taskData.Args.GetStringArg("action")
			dll, _ := taskData.Args.GetStringArg("dll")
			if dll == "" {
				dll = "ntdll.dll"
			}
			display := fmt.Sprintf("%s %s", action, dll)
			response.DisplayParams = &display
			if action == "" || action == "unhook" {
				createArtifact(taskData.Task.ID, "API Call",
					fmt.Sprintf("VirtualProtect + memcpy on %s .text section (EDR unhooking)", dll))
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
			if strings.Contains(responseText, "No hooks detected") {
				createArtifact(processResponse.TaskData.Task.ID, "Security Product",
					"[NTDLL] No hooks detected — ntdll.dll .text section clean")
			} else if strings.Contains(responseText, "hooked region") || strings.Contains(responseText, "Bytes restored") {
				// Count hooked regions or bytes restored
				hookCount := 0
				for _, line := range strings.Split(responseText, "\n") {
					if strings.Contains(line, "hooked region") || strings.Contains(strings.TrimSpace(line), "0x") {
						hookCount++
					}
				}
				if strings.Contains(responseText, "Bytes restored") {
					createArtifact(processResponse.TaskData.Task.ID, "Security Product",
						fmt.Sprintf("[NTDLL Unhook] Restored .text section — %d hooked regions patched", hookCount))
				} else {
					createArtifact(processResponse.TaskData.Task.ID, "Security Product",
						fmt.Sprintf("[NTDLL Check] %d hooked regions detected in ntdll.dll", hookCount))
				}
			}
			return response
		},
	})
}
