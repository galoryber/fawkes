package agentfunctions

import (
	"encoding/json"
	"fmt"
	"path/filepath"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
	"github.com/MythicMeta/MythicContainer/logging"
	"github.com/MythicMeta/MythicContainer/mythicrpc"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "enum-tokens",
		Description:         "Enumerate access tokens across all accessible processes (user, integrity, session)",
		HelpString:          "enum-tokens [-action list|unique] [-user filter]",
		Version:             1,
		SupportedUIFeatures: []string{},
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1134", "T1057"},
		ScriptOnlyCommand:   false,
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_WINDOWS},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:             "action",
				ModalDisplayName: "Action",
				CLIName:          "action",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:          []string{"list", "unique"},
				Description:      "list: show all process tokens. unique: show unique users with process counts",
				DefaultValue:     "list",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "user",
				ModalDisplayName: "User Filter",
				CLIName:          "user",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Filter results to tokens matching this user (case-insensitive substring match)",
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
		},
		AssociatedBrowserScript: &agentstructs.BrowserScript{
			ScriptPath: filepath.Join(".", "fawkes", "browserscripts", "enum_tokens_new.js"),
			Author:     "@galoryber",
		},
		TaskFunctionOPSECPre: nil,
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
			display := fmt.Sprintf("Token enumeration")
			response.DisplayParams = &display
			createArtifact(taskData.Task.ID, "API Call", "CreateToolhelp32Snapshot + OpenProcessToken across all processes")
			return response
		},
		TaskFunctionProcessResponse: func(processResponse agentstructs.PtTaskProcessResponseMessage) agentstructs.PTTaskProcessResponseMessageResponse {
			response := agentstructs.PTTaskProcessResponseMessageResponse{
				TaskID:  processResponse.TaskData.Task.ID,
				Success: true,
			}
			responseText, ok := processResponse.Response.(string)
			if !ok || responseText == "" || responseText == "[]" {
				return response
			}
			// Parse token entries from JSON output (both "list" and "unique" actions)
			type tokenInfo struct {
				PID       uint32 `json:"pid"`
				Process   string `json:"process"`
				User      string `json:"user"`
				Integrity string `json:"integrity"`
				Session   uint32 `json:"session"`
			}
			var tokens []tokenInfo
			if err := json.Unmarshal([]byte(responseText), &tokens); err != nil {
				return response
			}
			// Register unique users as tokens with Mythic
			host := processResponse.TaskData.Callback.Host
			seen := make(map[string]bool)
			var callbackTokens []mythicrpc.MythicRPCCallbackTokenData
			for _, t := range tokens {
				if t.User == "" || seen[t.User] {
					continue
				}
				seen[t.User] = true
				callbackTokens = append(callbackTokens, mythicrpc.MythicRPCCallbackTokenData{
					Action:  "add",
					Host:    &host,
					TokenId: uint64(processResponse.TaskData.Task.ID) + uint64(len(callbackTokens)),
					TokenInfo: &mythicrpc.MythicRPCTokenCreateTokenData{
						User:      t.User,
						ProcessID: int(t.PID),
						SessionID: int(t.Session),
					},
				})
			}
			if len(callbackTokens) > 0 {
				if _, err := mythicrpc.SendMythicRPCCallbackTokenCreate(mythicrpc.MythicRPCCallbackTokenCreateMessage{
					TaskID:         processResponse.TaskData.Task.ID,
					CallbackTokens: callbackTokens,
				}); err != nil {
					logging.LogError(err, "Failed to register enumerated tokens", "count", len(callbackTokens))
				}
			}
			return response
		},
	})
}
