package agentfunctions

import (
	"fmt"
	"path/filepath"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "modules",
		Description:         "List loaded modules/DLLs/libraries in a process with optional name filtering. Windows: DLLs via CreateToolhelp32Snapshot. Linux: shared libraries from /proc/pid/maps. macOS: dylibs via proc_info.",
		HelpString:          "modules [-pid <PID>] [-filter <name>]",
		Version:             2,
		MitreAttackMappings: []string{"T1057"},
		Author:              "@galoryber",
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_LINUX, agentstructs.SUPPORTED_OS_MACOS, agentstructs.SUPPORTED_OS_WINDOWS},
		},
		AssociatedBrowserScript: &agentstructs.BrowserScript{
			ScriptPath: filepath.Join(".", "fawkes", "browserscripts", "modules_new.js"),
			Author:     "@galoryber",
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:          "pid",
				CLIName:       "pid",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				Description:   "Target process ID (default: current process)",
				DefaultValue:  0,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     1,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:          "filter",
				CLIName:       "filter",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:   "Filter by module name or path (case-insensitive substring, e.g. 'amsi', 'clr')",
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
		TaskFunctionCreateTasking: func(task *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  task.Task.ID,
			}
			pid, _ := task.Args.GetNumberArg("pid")
			filter, _ := task.Args.GetStringArg("filter")

			display := "Modules"
			if pid != 0 {
				display += fmt.Sprintf(", pid=%d", int(pid))
			}
			if filter != "" {
				display += fmt.Sprintf(", filter=%s", filter)
			}
			response.DisplayParams = &display

			if display == "Modules" {
				if dp, err := task.Args.GetFinalArgs(); err == nil && dp != "" {
					response.DisplayParams = &dp
				}
			}
			return response
		},
	})
}
