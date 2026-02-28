package agentfunctions

import (
	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "autopatch",
		Description:         "Automatically patch a function by jumping to the nearest return (C3) instruction. Usage: autopatch <dll_name> <function_name> <num_bytes>",
		HelpString:          "autopatch amsi AmsiScanBuffer 300",
		Version:             1,
		MitreAttackMappings: []string{"T1055", "T1562.001"}, // Process Injection, Impair Defenses: Disable or Modify Tools
		SupportedUIFeatures: []string{},
		Author:              "@galoryber",
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_WINDOWS},
		},
		TaskFunctionParseArgString: func(args *agentstructs.PTTaskMessageArgsData, input string) error {
			args.SetManualArgs(input)
			return nil
		},
		TaskFunctionParseArgDictionary: func(args *agentstructs.PTTaskMessageArgsData, input map[string]interface{}) error {
			return args.LoadArgsFromDictionary(input)
		},
		TaskFunctionCreateTasking: func(task *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  task.Task.ID,
			}
			if displayParams, err := task.Args.GetFinalArgs(); err == nil {
				response.DisplayParams = &displayParams
			}
			createArtifact(task.Task.ID, "API Call", "Memory patching of EtwEventWrite/AmsiScanBuffer — scan for RET instruction and redirect function entry")
			return response
		},
	})
}
