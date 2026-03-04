package agentfunctions

import (
	"strconv"
	"strings"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "printspoofer",
		Description:         "PrintSpoofer privilege escalation — SeImpersonate to SYSTEM via Print Spooler named pipe impersonation (T1134.001)",
		HelpString:          "printspoofer [-timeout 15]",
		Version:             1,
		SupportedUIFeatures: []string{},
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1134.001"},
		ScriptOnlyCommand:   false,
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_WINDOWS},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:             "timeout",
				ModalDisplayName: "Timeout (seconds)",
				CLIName:          "timeout",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				Description:      "How long to wait for the spooler to connect (default: 15 seconds)",
				DefaultValue:     15,
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
			if err := args.LoadArgsFromJSONString(input); err == nil {
				return nil
			}
			// Plain text: parse -timeout N or just a number
			parts := strings.Fields(input)
			for i := 0; i < len(parts); i++ {
				if parts[i] == "-timeout" && i+1 < len(parts) {
					i++
					if t, err := strconv.Atoi(parts[i]); err == nil {
						args.SetArgValue("timeout", t)
					}
				} else if t, err := strconv.Atoi(parts[i]); err == nil {
					args.SetArgValue("timeout", t)
				}
			}
			return nil
		},
		TaskFunctionParseArgDictionary: func(args *agentstructs.PTTaskMessageArgsData, input map[string]interface{}) error {
			return args.LoadArgsFromDictionary(input)
		},
		TaskFunctionCreateTasking: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  taskData.Task.ID,
			}
			display := "SeImpersonate → SYSTEM via Print Spooler"
			response.DisplayParams = &display
			return response
		},
	})
}
