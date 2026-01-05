package agentfunctions

import (
	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "run",
		Description:         "run [command] - Execute a command in a child process",
		HelpString:          "run [command]",
		Version:             1,
		MitreAttackMappings: []string{"T1059"}, // Command and Scripting Interpreter
		SupportedUIFeatures: []string{},
		Author:              "@galoryber",
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_LINUX, agentstructs.SUPPORTED_OS_MACOS, agentstructs.SUPPORTED_OS_WINDOWS},
		},
		TaskFunctionParseArgString: func(args *agentstructs.PTTaskMessageArgsData, input string) error {
			// Simply pass the entire input string as the command to execute
			args.SetManualArgs(input)
			return nil
		},
		TaskFunctionParseArgDictionary: func(args *agentstructs.PTTaskMessageArgsData, input map[string]interface{}) error {
			// If called from dictionary (unlikely for this command), just convert to string
			if cmd, ok := input["command"].(string); ok {
				args.SetManualArgs(cmd)
			}
			return nil
		},
		TaskFunctionCreateTasking: func(task *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  task.Task.ID,
			}
			// Display the command being executed
			if displayParams, err := task.Args.GetFinalArgs(); err == nil {
				response.DisplayParams = &displayParams
			}
			return response
		},
	})
}
