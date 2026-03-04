package agentfunctions

import (
	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "pty",
		Description:         "Start an interactive PTY shell session (Linux/macOS only)",
		HelpString:          "pty",
		Version:             1,
		MitreAttackMappings: []string{"T1059"}, // Command and Scripting Interpreter
		SupportedUIFeatures: []string{"task_response:interactive"},
		Author:              "@galoryber",
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_LINUX, agentstructs.SUPPORTED_OS_MACOS},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:          "shell",
				CLIName:       "shell",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:   "Shell binary path (default: auto-detect from $SHELL or /bin/bash)",
				DefaultValue:  "",
	
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:          "rows",
				CLIName:       "rows",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				Description:   "Initial terminal rows (default: 24)",
				DefaultValue:  24,
	
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:          "cols",
				CLIName:       "cols",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				Description:   "Initial terminal columns (default: 80)",
				DefaultValue:  80,
	
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
		},
		TaskFunctionParseArgString: func(args *agentstructs.PTTaskMessageArgsData, input string) error {
			// PTY typically takes no arguments — just start it
			// But allow specifying a shell path as raw string
			if input != "" {
				args.SetArgValue("shell", input)
			}
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
			displayParams := "interactive PTY shell"
			if shell, err := task.Args.GetStringArg("shell"); err == nil && shell != "" {
				displayParams = "PTY: " + shell
			}
			response.DisplayParams = &displayParams
			return response
		},
	})
}
