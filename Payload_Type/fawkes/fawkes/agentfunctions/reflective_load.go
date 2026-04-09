package agentfunctions

import (
	"fmt"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "reflective-load",
		Description:         "Load a native PE (DLL) from memory into the current process without touching disk. Supports calling exported functions. Uses manual PE mapping: section copying, relocation fixups, import resolution, and DllMain invocation.",
		HelpString:          "reflective-load -dll_b64 <base64_dll> [-function <export_name>]",
		Version:             1,
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1620"}, // Reflective Code Loading
		SupportedUIFeatures: []string{},
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_WINDOWS},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:          "dll_b64",
				CLIName:       "dll_b64",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:   "Base64-encoded PE/DLL file to load into the current process",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: true,
						UIModalPosition:     1,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:          "function",
				CLIName:       "function",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:  "",
				Description:   "Optional: name of an exported function to call after loading (no-argument, returns uintptr)",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     2,
						GroupName:           "Default",
					},
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
			return agentstructs.PTTTaskOPSECPreTaskMessageResponse{
				TaskID:             taskData.Task.ID,
				Success:            true,
				OpsecPreBlocked:    false,
				OpsecPreMessage:    "OPSEC WARNING: Reflective DLL loading maps a DLL into memory without touching disk. Detectable by memory scanners looking for PE headers in non-image memory regions, unbacked executable memory (Sysmon 7), and ETW image load events.",
				OpsecPreBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
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
			function, _ := processResponse.TaskData.Args.GetStringArg("function")
			msg := "reflective-load: DLL loaded into memory"
			if function != "" {
				msg = fmt.Sprintf("reflective-load: DLL loaded, export %s called", function)
			}
			createArtifact(processResponse.TaskData.Task.ID, "Code Execution", msg)
			return response
		},
		TaskFunctionCreateTasking: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  taskData.Task.ID,
			}
			function, _ := taskData.Args.GetStringArg("function")
			if function != "" {
				display := fmt.Sprintf("Reflective load (export: %s)", function)
				response.DisplayParams = &display
			} else {
				display := fmt.Sprintf("Reflective load")
				response.DisplayParams = &display
			}
			createArtifact(taskData.Task.ID, "API Call", "Reflective DLL loading into memory")
			return response
		},
	})
}
