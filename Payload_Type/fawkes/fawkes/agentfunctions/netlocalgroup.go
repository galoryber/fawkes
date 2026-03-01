package agentfunctions

import (
	"fmt"
	"path/filepath"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name: "net-localgroup",
		AssociatedBrowserScript: &agentstructs.BrowserScript{
			ScriptPath: filepath.Join(".", "fawkes", "browserscripts", "netlocalgroup_new.js"),
			Author:     "@galoryber",
		},
		Description:         "Enumerate local groups and their members via NetLocalGroup APIs. Supports remote hosts. Use 'admins' action to quickly find local administrators.",
		HelpString:          "net-localgroup -action <list|members|admins> [-group <name>] [-server <hostname>]",
		Version:             1,
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1069.001"},
		SupportedUIFeatures: []string{},
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_WINDOWS},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:          "action",
				CLIName:       "action",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:       []string{"list", "members", "admins"},
				DefaultValue:  "list",
				Description:   "Action: list (all groups), members (group membership), admins (shortcut for Administrators group)",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     1,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:          "group",
				CLIName:       "group",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:  "",
				Description:   "Group name to enumerate members for (required for 'members' action). Examples: Administrators, \"Remote Desktop Users\", \"Backup Operators\"",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     2,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:          "server",
				CLIName:       "server",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:  "",
				Description:   "Remote server hostname or IP to query (blank = local machine). UNC prefix added automatically.",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     3,
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
			group, _ := taskData.Args.GetStringArg("group")
			server, _ := taskData.Args.GetStringArg("server")
			display := fmt.Sprintf("action: %s", action)
			if group != "" {
				display += fmt.Sprintf(", group: %s", group)
			}
			if server != "" {
				display += fmt.Sprintf(", server: %s", server)
			}
			response.DisplayParams = &display
			return response
		},
	})
}
