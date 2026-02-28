package agentfunctions

import (
	"fmt"
	"strings"

	"github.com/MythicMeta/MythicContainer/logging"
	"github.com/MythicMeta/MythicContainer/mythicrpc"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "steal-token",
		Description:         "Steal and impersonate a token from another process",
		HelpString:          "steal-token <PID>",
		Version:             1,
		SupportedUIFeatures: []string{},
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1134.001"},
		ScriptOnlyCommand:   false,
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:             "pid",
				ModalDisplayName: "Process ID",
				CLIName:          "pid",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				Description:      "Process ID to steal token from (e.g., lsass.exe, winlogon.exe)",
				Choices:          []string{},
				DefaultValue:     0,
				SupportedAgents:  []string{},
				ChoicesAreAllCommands:                   false,
				ChoicesAreLoadedCommands:                false,
				FilterCommandChoicesByCommandAttributes: map[string]string{},
				DynamicQueryFunction:                    nil,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: true,
						UIModalPosition:     1,
						GroupName:           "Default",
					},
				},
			},
		},
		AssociatedBrowserScript: nil,
		TaskFunctionOPSECPre:    nil,
		TaskFunctionParseArgString: func(args *agentstructs.PTTaskMessageArgsData, input string) error {
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
			pid, _ := taskData.Args.GetNumberArg("pid")
			createArtifact(taskData.Task.ID, "Token Steal", fmt.Sprintf("OpenProcess + OpenProcessToken + DuplicateTokenEx on PID %d", int(pid)))
			return response
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

			// Only track on successful steal (output contains "New:")
			if !strings.Contains(responseText, "New:") {
				return response
			}

			// Parse "New: DOMAIN\user" from output
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

			// Get source PID for context
			pid, _ := processResponse.TaskData.Args.GetNumberArg("pid")

			// Register token with Mythic's callback token tracker
			host := processResponse.TaskData.Callback.Host
			_, err := mythicrpc.SendMythicRPCCallbackTokenCreate(mythicrpc.MythicRPCCallbackTokenCreateMessage{
				TaskID: processResponse.TaskData.Task.ID,
				CallbackTokens: []mythicrpc.MythicRPCCallbackTokenData{
					{
						Action:  "add",
						Host:    &host,
						TokenId: uint64(processResponse.TaskData.Task.ID),
						TokenInfo: &mythicrpc.MythicRPCTokenCreateTokenData{
							User:      user,
							ProcessID: int(pid),
						},
					},
				},
			})
			if err != nil {
				logging.LogError(err, "Failed to register stolen token with Mythic", "user", user, "pid", int(pid))
			}

			return response
		},
	})
}
