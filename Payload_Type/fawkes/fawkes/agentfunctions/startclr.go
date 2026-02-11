package agentfunctions

import (
	"encoding/json"
	"fmt"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
	"github.com/MythicMeta/MythicContainer/logging"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "start-clr",
		Description:         "Initialize the .NET CLR runtime with optional AMSI/ETW patching",
		HelpString:          "start-clr",
		Version:             2,
		MitreAttackMappings: []string{"T1055.001", "T1620", "T1562.001"},
		SupportedUIFeatures: []string{},
		Author:              "@galoryber",
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_WINDOWS},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:             "amsi_patch",
				ModalDisplayName: "AMSI Patch Method",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Description:      "Method to patch AMSI (AmsiScanBuffer). Autopatch writes a JMP-to-RET. Hardware Breakpoint uses debug registers + VEH.",
				Choices:          []string{"None", "Autopatch", "Hardware Breakpoint"},
				DefaultValue:     "None",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: true,
						UIModalPosition:     1,
					},
				},
			},
			{
				Name:             "etw_patch",
				ModalDisplayName: "ETW Patch Method",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Description:      "Method to patch ETW (EtwEventWrite). Autopatch writes a JMP-to-RET. Hardware Breakpoint uses debug registers + VEH.",
				Choices:          []string{"None", "Autopatch", "Hardware Breakpoint"},
				DefaultValue:     "None",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: true,
						UIModalPosition:     2,
					},
				},
			},
		},
		TaskFunctionParseArgString: func(args *agentstructs.PTTaskMessageArgsData, input string) error {
			// Accept empty input for backward compat (defaults to None/None)
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

			amsiPatch, err := taskData.Args.GetStringArg("amsi_patch")
			if err != nil {
				logging.LogError(err, "Failed to get amsi_patch arg, defaulting to None")
				amsiPatch = "None"
			}

			etwPatch, err := taskData.Args.GetStringArg("etw_patch")
			if err != nil {
				logging.LogError(err, "Failed to get etw_patch arg, defaulting to None")
				etwPatch = "None"
			}

			displayParams := fmt.Sprintf("CLR Init | AMSI: %s | ETW: %s", amsiPatch, etwPatch)
			response.DisplayParams = &displayParams

			params := map[string]interface{}{
				"amsi_patch": amsiPatch,
				"etw_patch":  etwPatch,
			}

			paramsJSON, err := json.Marshal(params)
			if err != nil {
				logging.LogError(err, "Failed to marshal parameters")
				response.Success = false
				response.Error = "Failed to create task parameters: " + err.Error()
				return response
			}

			taskData.Args.SetManualArgs(string(paramsJSON))
			return response
		},
	})
}
