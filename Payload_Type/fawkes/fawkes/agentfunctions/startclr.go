package agentfunctions

import (
	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "start-clr",
		Description:         "start-clr - Initialize the .NET CLR runtime and load AMSI.dll",
		HelpString:          "start-clr",
		Version:             1,
		MitreAttackMappings: []string{"T1055.001", "T1620"}, // Process Injection: Dynamic-link Library Injection, Reflective Code Loading
		SupportedUIFeatures: []string{},
		Author:              "@galoryber",
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_WINDOWS},
		},
		TaskFunctionParseArgString: func(args *agentstructs.PTTaskMessageArgsData, input string) error {
			// No arguments needed for this command
			return nil
		},
		TaskFunctionParseArgDictionary: func(args *agentstructs.PTTaskMessageArgsData, input map[string]interface{}) error {
			// No arguments needed for this command
			return nil
		},
		TaskFunctionCreateTasking: func(task *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  task.Task.ID,
			}
			displayParams := "Initialize CLR and load AMSI.dll"
			response.DisplayParams = &displayParams
			return response
		},
	})
}
