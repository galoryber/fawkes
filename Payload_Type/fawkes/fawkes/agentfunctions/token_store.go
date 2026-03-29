package agentfunctions

import (
	"strings"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
	"github.com/MythicMeta/MythicContainer/logging"
	"github.com/MythicMeta/MythicContainer/mythicrpc"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "token-store",
		Description:         "token-store -action <save|list|use|remove> [-name label] - Manage named token store for quick identity switching. Save stolen/created tokens, list all saved, switch between them, or remove entries.",
		HelpString:          "token-store -action save -name admin    # save current token\ntoken-store -action list                 # list all saved tokens\ntoken-store -action use -name admin      # switch to saved token\ntoken-store -action remove -name admin   # remove from store",
		Version:             1,
		MitreAttackMappings: []string{"T1134.001"}, // Access Token Manipulation: Token Impersonation/Theft
		Author:              "@galoryber",
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_WINDOWS},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:          "action",
				CLIName:       "action",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Description:   "Action to perform",
				DefaultValue:  "list",
				Choices:       []string{"save", "list", "use", "remove"},
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: true,
						UIModalPosition:     1,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:          "name",
				CLIName:       "name",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:   "Label for the token (required for save/use/remove)",
				DefaultValue:  "",
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
		TaskFunctionProcessResponse: func(processResponse agentstructs.PtTaskProcessResponseMessage) agentstructs.PTTaskProcessResponseMessageResponse {
			response := agentstructs.PTTaskProcessResponseMessageResponse{
				TaskID:  processResponse.TaskData.Task.ID,
				Success: true,
			}
			responseText, ok := processResponse.Response.(string)
			if !ok || responseText == "" {
				return response
			}
			// When action=use succeeds, output contains "New: DOMAIN\user"
			// Register the token with Mythic's callback token tracker
			if !strings.Contains(responseText, "New:") {
				return response
			}
			user := ""
			for _, line := range strings.Split(responseText, "\n") {
				if strings.HasPrefix(strings.TrimSpace(line), "New:") {
					user = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "New:"))
					break
				}
			}
			if user == "" {
				return response
			}
			host := processResponse.TaskData.Callback.Host
			_, err := mythicrpc.SendMythicRPCCallbackTokenCreate(mythicrpc.MythicRPCCallbackTokenCreateMessage{
				TaskID: processResponse.TaskData.Task.ID,
				CallbackTokens: []mythicrpc.MythicRPCCallbackTokenData{
					{
						Action:  "add",
						Host:    &host,
						TokenId: uint64(processResponse.TaskData.Task.ID),
						TokenInfo: &mythicrpc.MythicRPCTokenCreateTokenData{
							User: user,
						},
					},
				},
			})
			if err != nil {
				logging.LogError(err, "Failed to register token-store token with Mythic", "user", user)
			}
			return response
		},
		TaskFunctionCreateTasking: func(task *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  task.Task.ID,
			}
			if displayParams, err := task.Args.GetFinalArgs(); err == nil && displayParams != "" {
				response.DisplayParams = &displayParams
			}
			return response
		},
	})
}
