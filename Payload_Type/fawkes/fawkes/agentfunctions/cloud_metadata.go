package agentfunctions

import (
	"fmt"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "cloud-metadata",
		Description:         "Probe cloud instance metadata services (AWS/Azure/GCP/DigitalOcean) for credentials, identity, and configuration. Supports IMDSv2 for AWS.",
		HelpString:          "cloud-metadata -action detect\ncloud-metadata -action creds\ncloud-metadata -action all -provider aws",
		Version:             1,
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1552.005", "T1580"},
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{
				agentstructs.SUPPORTED_OS_WINDOWS,
				agentstructs.SUPPORTED_OS_LINUX,
				agentstructs.SUPPORTED_OS_MACOS,
			},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:          "action",
				CLIName:       "action",
				Description:   "Action to perform: detect, all, creds, identity, userdata, network",
				DefaultValue:  "detect",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:       []string{"detect", "all", "creds", "identity", "userdata", "network"},
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:          "provider",
				CLIName:       "provider",
				Description:   "Cloud provider to query (auto-detects if not specified)",
				DefaultValue:  "auto",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:       []string{"auto", "aws", "azure", "gcp", "digitalocean"},
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:          "timeout",
				CLIName:       "timeout",
				Description:   "Per-request timeout in seconds (default: 3)",
				DefaultValue:  3,
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
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
		TaskFunctionParseArgDictionary: func(args *agentstructs.PTTaskMessageArgsData, input map[string]interface{}) error {
			return args.LoadArgsFromDictionary(input)
		},
		TaskFunctionCreateTasking: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  taskData.Task.ID,
			}
			action, _ := taskData.Args.GetStringArg("action")
			provider, _ := taskData.Args.GetStringArg("provider")
			display := action
			if provider != "" && provider != "auto" {
				display += fmt.Sprintf(" (%s)", provider)
			}
			response.DisplayParams = &display
			return response
		},
	})
}
