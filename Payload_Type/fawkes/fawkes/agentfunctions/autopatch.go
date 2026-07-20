package agentfunctions

import (
	"fmt"
	"path/filepath"
	"strings"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "autopatch",
		Description:         "Patch security hooks in memory. Default: C3 Jump technique (searches for nearest RET and writes a JMP to it). Alternative: byte-overwrite strategies (xor-ret, ret, nop-ret, mov-ret). Actions: scan, patch-amsi, patch-etw, patch-all.",
		HelpString:          "# Patch all with C3 Jump (default)\nautopatch -action patch-all\n# Scan AMSI/ETW targets for patchability\nautopatch -action scan\n# Patch AMSI with C3 Jump\nautopatch -action patch-amsi\n# Patch with byte-overwrite strategy\nautopatch -action patch-all -strategy xor-ret\n# Custom target with C3 Jump\nautopatch -dll_name amsi -function_name AmsiScanBuffer -num_bytes 300",
		Version:             3,
		MitreAttackMappings: []string{"T1562.001"},
		SupportedUIFeatures: []string{},
		Author:              "@galoryber",
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_WINDOWS},
			FilterCommandAvailabilityByAgentBuildParameters: map[string]string{"selected_os": "Windows"},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:          "action",
				CLIName:       "action",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:       []string{"patch-all", "patch-amsi", "patch-etw", "scan"},
				DefaultValue:  "patch-all",
				Description:   "patch-all (patch all known targets), patch-amsi (patch AmsiScanBuffer), patch-etw (patch EtwEventWrite), scan (check targets without patching)",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, UIModalPosition: 1, GroupName: "C3 Jump"},
					{ParameterIsRequired: false, UIModalPosition: 1, GroupName: "Byte Overwrite"},
				},
			},
			{
				Name:          "strategy",
				CLIName:       "strategy",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:       []string{"xor-ret", "ret", "nop-ret", "mov-ret"},
				DefaultValue:  "xor-ret",
				Description:   "Byte-overwrite strategy: xor-ret (returns 0/S_OK), ret (immediate return), nop-ret (NOP+NOP+RET), mov-ret (returns 1/TRUE)",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: true, UIModalPosition: 2, GroupName: "Byte Overwrite"},
				},
			},
			{
				Name:          "dll_name",
				CLIName:       "dll_name",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:  "",
				Description:   "DLL containing the target function (e.g., amsi, ntdll.dll)",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: true, UIModalPosition: 1, GroupName: "Custom Target"},
				},
			},
			{
				Name:          "function_name",
				CLIName:       "function_name",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:  "",
				Description:   "Function name to patch (e.g., AmsiScanBuffer, EtwEventWrite)",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: true, UIModalPosition: 2, GroupName: "Custom Target"},
				},
			},
			{
				Name:          "num_bytes",
				CLIName:       "num_bytes",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				DefaultValue:  300,
				Description:   "Search range in bytes — how far forward/backward to scan for a C3 (RET) instruction",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, UIModalPosition: 3, GroupName: "Custom Target"},
				},
			},
		},
		TaskFunctionOPSECPost: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskOPSECPostTaskMessageResponse {
			return agentstructs.PTTaskOPSECPostTaskMessageResponse{
				TaskID:              taskData.Task.ID,
				Success:             true,
				OpsecPostBlocked:    false,
				OpsecPostMessage:    "OPSEC AUDIT: AMSI/ETW patching completed. Memory patches to amsi.dll/ntdll.dll modify process memory. EDR products monitoring for in-memory patches may detect the modification pattern. Patches persist until process restart.",
				OpsecPostBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		AssociatedBrowserScript: &agentstructs.BrowserScript{
			ScriptPath: filepath.Join(".", "fawkes", "browserscripts", "autopatch_new.js"),
			Author:     "@galoryber",
		},
		TaskFunctionParseArgString: func(args *agentstructs.PTTaskMessageArgsData, input string) error {
			if input == "" {
				return nil
			}
			if err := args.LoadArgsFromJSONString(input); err != nil {
				args.SetManualArgs(input)
			}
			return nil
		},
		TaskFunctionParseArgDictionary: func(args *agentstructs.PTTaskMessageArgsData, input map[string]interface{}) error {
			return args.LoadArgsFromDictionary(input)
		},
		TaskFunctionOPSECPre: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTTaskOPSECPreTaskMessageResponse {
			action, _ := taskData.Args.GetStringArg("action")
			var msg string
			if action == "scan" {
				msg = "OPSEC WARNING: Scanning AMSI/ETW function memory for patchability (T1562.001). Pattern scan reads function prologues via ReadProcessMemory. Lower risk than patching but still detectable."
			} else {
				msg = "OPSEC WARNING: Patching security hooks in memory (T1562.001). Modifying AMSI/ETW trampolines is a well-known evasion technique. EDR products monitor for hook integrity violations and memory protection changes."
			}
			return agentstructs.PTTTaskOPSECPreTaskMessageResponse{
				TaskID: taskData.Task.ID, Success: true,
				OpsecPreBlocked: false, OpsecPreMessage: msg,
				OpsecPreBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionProcessResponse: func(processResponse agentstructs.PtTaskProcessResponseMessage) agentstructs.PTTaskProcessResponseMessageResponse {
			response := agentstructs.PTTaskProcessResponseMessageResponse{
				TaskID:  processResponse.TaskData.Task.ID,
				Success: true,
			}
			action, _ := processResponse.TaskData.Args.GetStringArg("action")
			responseText, ok := processResponse.Response.(string)
			if !ok || responseText == "" {
				return response
			}
			if action == "scan" {
				createArtifact(processResponse.TaskData.Task.ID, "Security Discovery",
					"autopatch scan: security hook patchability assessed")
			} else if strings.Contains(responseText, "patched") || strings.Contains(responseText, "success") {
				createArtifact(processResponse.TaskData.Task.ID, "Defense Evasion",
					fmt.Sprintf("autopatch %s: security hooks patched successfully", action))
			}
			return response
		},
		TaskFunctionCreateTasking: func(task *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  task.Task.ID,
			}
			action, _ := task.Args.GetStringArg("action")
			strategy, _ := task.Args.GetStringArg("strategy")
			dllName, _ := task.Args.GetStringArg("dll_name")
			if dllName != "" {
				display := fmt.Sprintf("C3 Jump: %s!%s", dllName, func() string { s, _ := task.Args.GetStringArg("function_name"); return s }())
				response.DisplayParams = &display
			} else if action != "" {
				if strategy != "" && action != "scan" {
					display := fmt.Sprintf("action: %s, strategy: %s", action, strategy)
					response.DisplayParams = &display
				} else {
					technique := "C3 Jump"
					if strategy != "" {
						technique = strategy
					}
					display := fmt.Sprintf("action: %s, technique: %s", action, technique)
					response.DisplayParams = &display
				}
			}
			if action != "scan" {
				createArtifact(task.Task.ID, "API Call", "VirtualProtect + WriteProcessMemory on security DLL function")
				logOperationEvent(task.Task.ID,
					fmt.Sprintf("[DEFENSE EVASION] autopatch %s: patching security hooks on %s", action, task.Callback.Host), true)
			}
			return response
		},
	})
}
