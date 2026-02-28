package agentfunctions

import (
	"fmt"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "argue",
		Description:         "Execute a command with spoofed process arguments. Creates process with fake command-line args (visible to Sysmon/EDR), then patches PEB to real args before resume. Defeats Event ID 1 command-line logging.",
		HelpString:          "argue -command \"cmd.exe /c whoami\" -spoof \"cmd.exe /c echo hello\"",
		Version:             1,
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1564.010"}, // Process Argument Spoofing
		SupportedUIFeatures: []string{},
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_WINDOWS},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:          "command",
				CLIName:       "command",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:   "The real command to execute (e.g., cmd.exe /c whoami /all)",
				DefaultValue:  "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: true,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:          "spoof",
				CLIName:       "spoof",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:   "Fake command line shown in logs (default: executable name with no args). Should use the same executable as the real command.",
				DefaultValue:  "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
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
		TaskFunctionCreateTasking: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  taskData.Task.ID,
			}

			command, err := taskData.Args.GetStringArg("command")
			if err != nil || command == "" {
				response.Success = false
				response.Error = "command parameter is required"
				return response
			}

			spoof, _ := taskData.Args.GetStringArg("spoof")

			displayMsg := fmt.Sprintf("Executing with spoofed args: %s", command)
			if spoof != "" {
				displayMsg += fmt.Sprintf(" (logged as: %s)", spoof)
			}
			response.DisplayParams = &displayMsg

			// Report artifact: process argument spoofing
			spoofDisplay := spoof
			if spoofDisplay == "" {
				spoofDisplay = "(executable name only)"
			}
			createArtifact(taskData.Task.ID, "API Call", fmt.Sprintf("Process argument spoofing — spoofed: %s, real: %s", spoofDisplay, command))

			return response
		},
	})
}
