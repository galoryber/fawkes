package agentfunctions

import (
	"fmt"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
	"github.com/MythicMeta/MythicContainer/mythicrpc"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "defender",
		Description:         "Query Windows Defender status, manage exclusions, and view threat detections. Uses WMI (MSFT_MpComputerStatus) and registry APIs.",
		HelpString:          "defender -action <status|exclusions|add-exclusion|remove-exclusion|threats> [-type <path|process|extension>] [-value <exclusion_value>]",
		Version:             1,
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1562.001"}, // Impair Defenses: Disable or Modify Tools
		SupportedUIFeatures: []string{},
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_WINDOWS},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:          "action",
				CLIName:       "action",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:       []string{"status", "exclusions", "add-exclusion", "remove-exclusion", "threats"},
				DefaultValue:  "status",
				Description:   "Action: check status, list/add/remove exclusions, or view threat history",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: true,
						UIModalPosition:     1,
						GroupName:            "Default",
					},
				},
			},
			{
				Name:          "type",
				CLIName:       "type",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:       []string{"path", "process", "extension"},
				DefaultValue:  "path",
				Description:   "Exclusion type: path, process, or extension (for add/remove-exclusion)",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     2,
						GroupName:            "Default",
					},
				},
			},
			{
				Name:          "value",
				CLIName:       "value",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:  "",
				Description:   "Exclusion value (e.g., 'C:\\Users\\setup\\Downloads', 'payload.exe', '.dat')",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     3,
						GroupName:            "Default",
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
			action, _ := taskData.Args.GetStringArg("action")
			value, _ := taskData.Args.GetStringArg("value")
			exType, _ := taskData.Args.GetStringArg("type")
			switch action {
			case "add-exclusion":
				mythicrpc.SendMythicRPCArtifactCreate(mythicrpc.MythicRPCArtifactCreateMessage{
					TaskID:           taskData.Task.ID,
					BaseArtifactType: "Registry Write",
					ArtifactMessage:  fmt.Sprintf("Defender %s exclusion added: %s", exType, value),
				})
			case "remove-exclusion":
				mythicrpc.SendMythicRPCArtifactCreate(mythicrpc.MythicRPCArtifactCreateMessage{
					TaskID:           taskData.Task.ID,
					BaseArtifactType: "Registry Write",
					ArtifactMessage:  fmt.Sprintf("Defender %s exclusion removed: %s", exType, value),
				})
			}
			return response
		},
	})
}
