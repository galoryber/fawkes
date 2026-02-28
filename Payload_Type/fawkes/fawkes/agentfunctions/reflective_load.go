package agentfunctions

import (
	"fmt"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
	"github.com/MythicMeta/MythicContainer/mythicrpc"
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
			mythicrpc.SendMythicRPCArtifactCreate(mythicrpc.MythicRPCArtifactCreateMessage{
				TaskID:           taskData.Task.ID,
				BaseArtifactType: "Process Inject",
				ArtifactMessage:  fmt.Sprintf("Reflective PE load into current process (self-injection via manual PE mapping)"),
			})
			return response
		},
	})
}
