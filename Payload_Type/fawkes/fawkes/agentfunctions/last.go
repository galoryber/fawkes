package agentfunctions

import (
	"fmt"
	"path/filepath"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name: "last",
		AssociatedBrowserScript: &agentstructs.BrowserScript{
			ScriptPath: filepath.Join(".", "fawkes", "browserscripts", "last_new.js"),
			Author:     "@galoryber",
		},
		Description:         "Show recent login history. Linux: parses wtmp/utmp or auth.log. Windows: queries Security event log (4624). macOS: uses last command.",
		HelpString:          "last\nlast -count 50\nlast -user admin",
		Version:             1,
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1087.001"},
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{
				agentstructs.SUPPORTED_OS_WINDOWS,
				agentstructs.SUPPORTED_OS_LINUX,
				agentstructs.SUPPORTED_OS_MACOS,
			},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:          "count",
				CLIName:       "count",
				Description:   "Number of entries to show (default: 25)",
				DefaultValue:  25,
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:          "user",
				CLIName:       "user",
				Description:   "Filter by username",
				DefaultValue:  "",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
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
			response := agentstructs.PTTaskCreateTaskingMessageResponse{Success: true, TaskID: taskData.Task.ID}
			count, _ := taskData.Args.GetNumberArg("count")
			user, _ := taskData.Args.GetStringArg("user")
			dp := ""
			if user != "" {
				dp = fmt.Sprintf("user: %s", user)
			}
			if count > 0 && int(count) != 25 {
				if dp != "" {
					dp += ", "
				}
				dp += fmt.Sprintf("count: %d", int(count))
			}
			if dp != "" {
				response.DisplayParams = &dp
			}
			return response
		},
	})
}
