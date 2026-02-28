package agentfunctions

import (
	"fmt"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "crontab",
		Description:         "List, add, or remove cron jobs for persistence (T1053.003)",
		HelpString:          "crontab -action <list|add|remove> [-entry <cron line>] [-program <path>] [-schedule <cron schedule>] [-user <username>]",
		Version:             1,
		SupportedUIFeatures: []string{},
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1053.003"},
		ScriptOnlyCommand:   false,
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_LINUX, agentstructs.SUPPORTED_OS_MACOS},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:             "action",
				ModalDisplayName: "Action",
				CLIName:          "action",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:          []string{"list", "add", "remove"},
				Description:      "Action to perform: list current cron jobs, add a new entry, or remove an entry",
				DefaultValue:     "list",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: true,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "entry",
				ModalDisplayName: "Cron Entry",
				CLIName:          "entry",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Raw cron entry line (e.g., '*/5 * * * * /path/to/agent'). For remove, substring to match.",
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
				ModalDisplayName: "Program Path",
				CLIName:          "program",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Path to program (alternative to raw entry — combined with schedule)",
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
				Description:      "Arguments for the program",
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "schedule",
				ModalDisplayName: "Schedule",
				CLIName:          "schedule",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Cron schedule (e.g., '@reboot', '*/5 * * * *', '0 0 * * *'). Default: @reboot",
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
				ModalDisplayName: "User",
				CLIName:          "user",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Target user for crontab operations (requires privileges). Default: current user.",
				DefaultValue:     "",
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
			display := fmt.Sprintf("%s", action)
			response.DisplayParams = &display
			if action == "add" || action == "remove" {
				entry, _ := taskData.Args.GetStringArg("entry")
				program, _ := taskData.Args.GetStringArg("program")
				user, _ := taskData.Args.GetStringArg("user")
				msg := fmt.Sprintf("crontab %s", action)
				if entry != "" {
					msg += fmt.Sprintf(" entry=%s", entry)
				}
				if program != "" {
					msg += fmt.Sprintf(" program=%s", program)
				}
				if user != "" {
					msg += fmt.Sprintf(" user=%s", user)
				}
				createArtifact(taskData.Task.ID, "File Write", msg)
			}
			return response
		},
	})
}
