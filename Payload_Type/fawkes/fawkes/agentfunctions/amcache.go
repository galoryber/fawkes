package agentfunctions

import (
	"fmt"
	"path/filepath"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name: "amcache",
		AssociatedBrowserScript: &agentstructs.BrowserScript{
			ScriptPath: filepath.Join(".", "fawkes", "browserscripts", "amcache_new.js"),
			Author:     "@galoryber",
		},
		Description:         "Query and clean forensic execution artifacts. Windows: Shimcache/AppCompatCache. Linux: recently-used.xbel, thumbnails, GNOME Tracker. macOS: recent items, KnowledgeC, quarantine events.",
		HelpString:          "amcache -action <query|search|delete|clear> [-name <pattern>] [-count <n>]",
		Version:             2,
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1070.004"}, // Indicator Removal: File Deletion
		SupportedUIFeatures: []string{},
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_WINDOWS, agentstructs.SUPPORTED_OS_LINUX, agentstructs.SUPPORTED_OS_MACOS},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:          "action",
				CLIName:       "action",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:       []string{"query", "search", "delete", "clear"},
				DefaultValue:  "query",
				Description:   "Action: query (list entries), search (find by name), delete (remove matching), clear (remove all)",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     1,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:          "name",
				CLIName:       "name",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:  "",
				Description:   "Executable name or path pattern to search/delete (case-insensitive substring match)",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     2,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:          "count",
				CLIName:       "count",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				DefaultValue:  50,
				Description:   "Maximum entries to display (for query action)",
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
		TaskFunctionOPSECPre: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTTaskOPSECPreTaskMessageResponse {
			return agentstructs.PTTTaskOPSECPreTaskMessageResponse{
				TaskID:             taskData.Task.ID,
				Success:            true,
				OpsecPreBlocked:    false,
				OpsecPreMessage:    "OPSEC WARNING: Forensic artifact manipulation. Windows: modifies AppCompatCache registry key. Linux: modifies recently-used.xbel, thumbnails, tracker DB. macOS: removes recent items, KnowledgeC, quarantine events. Detectable by integrity monitoring and forensic timeline analysis.",
				OpsecPreBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionCreateTasking: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			resp := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  taskData.Task.ID,
			}

			action, _ := taskData.Args.GetStringArg("action")
			display := action
			name, _ := taskData.Args.GetStringArg("name")
			if name != "" {
				display += fmt.Sprintf(" %s", name)
			}
			resp.DisplayParams = &display

			if action == "delete" || action == "clear" {
				msg := "AMCache entry deletion: HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCompatCache\\AppCompatCache"
				if name != "" {
					msg += fmt.Sprintf(" (filter: %s)", name)
				}
				createArtifact(taskData.Task.ID, "Registry Write", msg)
			}

			return resp
		},
	})
}
