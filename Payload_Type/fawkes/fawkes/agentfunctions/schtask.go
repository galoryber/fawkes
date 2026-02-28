package agentfunctions

import (
	"fmt"
	"path/filepath"
	"strings"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name: "schtask",
		AssociatedBrowserScript: &agentstructs.BrowserScript{
			ScriptPath: filepath.Join(".", "fawkes", "browserscripts", "schtask_new.js"),
			Author:     "@galoryber",
		},
		Description:         "Create, query, run, or delete Windows scheduled tasks via COM API (T1053.005)",
		HelpString:          "schtask -action <create|query|delete|run|list> -name <task_name> [-program <path>] [-args <arguments>] [-trigger <ONLOGON|DAILY|...>] [-time <HH:MM>] [-user <account>] [-run_now]",
		Version:             1,
		SupportedUIFeatures: []string{},
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1053.005"},
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
				Choices:          []string{"create", "query", "delete", "run", "list"},
				Description:      "Action to perform: create, query, delete, run, or list tasks",
				DefaultValue:     "query",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: true,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "name",
				ModalDisplayName: "Task Name",
				CLIName:          "name",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Name of the scheduled task (e.g., \\MyTask or \\Microsoft\\Windows\\MyTask)",
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "program",
				ModalDisplayName: "Program",
				CLIName:          "program",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Path to the program to execute (required for create)",
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "args",
				ModalDisplayName: "Program Arguments",
				CLIName:          "args",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Arguments to pass to the program",
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "trigger",
				ModalDisplayName: "Trigger",
				CLIName:          "trigger",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:          []string{"ONLOGON", "ONSTART", "DAILY", "WEEKLY", "MONTHLY", "ONCE", "ONIDLE"},
				Description:      "When the task should run (default: ONLOGON)",
				DefaultValue:     "ONLOGON",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "time",
				ModalDisplayName: "Start Time",
				CLIName:          "time",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Start time for time-based triggers (HH:MM format, e.g., 09:00)",
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "user",
				ModalDisplayName: "Run As User",
				CLIName:          "user",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "User account to run the task as (e.g., SYSTEM, NT AUTHORITY\\SYSTEM)",
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "run_now",
				ModalDisplayName: "Run Immediately",
				CLIName:          "run_now",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_BOOLEAN,
				Description:      "Execute the task immediately after creation",
				DefaultValue:     false,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
		},
		TaskFunctionOPSECPre:    nil,
		TaskFunctionParseArgString: func(args *agentstructs.PTTaskMessageArgsData, input string) error {
			if input == "" {
				return nil
			}
			// Try JSON first (from API/modal)
			if err := args.LoadArgsFromJSONString(input); err == nil {
				return nil
			}
			// Plain string: first word is action (list, query, create, delete, run)
			// Second word (if present) is task name
			parts := strings.Fields(input)
			if len(parts) >= 1 {
				args.SetArgValue("action", parts[0])
			}
			if len(parts) >= 2 {
				args.SetArgValue("name", parts[1])
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
			action, _ := taskData.Args.GetStringArg("action")
			name, _ := taskData.Args.GetStringArg("name")
			display := fmt.Sprintf("%s %s", action, name)
			response.DisplayParams = &display
			switch action {
			case "create":
				program, _ := taskData.Args.GetStringArg("program")
				createArtifact(taskData.Task.ID, "API Call", fmt.Sprintf("ITaskFolder.RegisterTaskDefinition(%q, exec=%q)", name, program))
			case "delete":
				createArtifact(taskData.Task.ID, "API Call", fmt.Sprintf("ITaskFolder.DeleteTask(%q)", name))
			case "run":
				createArtifact(taskData.Task.ID, "API Call", fmt.Sprintf("IRegisteredTask.Run(%q)", name))
			}
			return response
		},
		TaskFunctionProcessResponse: nil,
	})
}
