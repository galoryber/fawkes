package agentfunctions

import (
	"fmt"

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
		TaskFunctionOPSECPre:    nil,
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
			if action == "" || action == "unhook" {
				createArtifact(taskData.Task.ID, "API Call",
					fmt.Sprintf("VirtualProtect + memcpy on %s .text section (EDR unhooking)", dll))
			}
			return response
		},
		TaskFunctionProcessResponse: nil,
	})
}
