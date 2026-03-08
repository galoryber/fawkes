package agentfunctions

import (
	"fmt"
	"path/filepath"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name: "df",
		AssociatedBrowserScript: &agentstructs.BrowserScript{
			ScriptPath: filepath.Join(".", "fawkes", "browserscripts", "df_new.js"),
			Author:     "@galoryber",
		},
		Description:         "Report filesystem disk space usage with optional filtering by device, mount point, or filesystem type.",
		HelpString:          "df [-filesystem <device>] [-mount_point <path>] [-fstype <type>]",
		Version:             2,
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1082"},
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{
				agentstructs.SUPPORTED_OS_WINDOWS,
				agentstructs.SUPPORTED_OS_LINUX,
				agentstructs.SUPPORTED_OS_MACOS,
			},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:          "filesystem",
				CLIName:       "filesystem",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:  "",
				Description:   "Filter by device/filesystem name (substring match)",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     1,
						GroupName:            "Default",
					},
				},
			},
			{
				Name:          "mount_point",
				CLIName:       "mount_point",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:  "",
				Description:   "Filter by mount point path (substring match)",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     2,
						GroupName:            "Default",
					},
				},
			},
			{
				Name:          "fstype",
				CLIName:       "fstype",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:  "",
				Description:   "Filter by filesystem type (case-insensitive, e.g. 'ext4', 'ntfs')",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     3,
						GroupName:            "Default",
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
			fs, _ := taskData.Args.GetStringArg("filesystem")
			mp, _ := taskData.Args.GetStringArg("mount_point")
			ft, _ := taskData.Args.GetStringArg("fstype")

			display := "Disk space"
			if fs != "" {
				display += fmt.Sprintf(", filesystem=%s", fs)
			}
			if mp != "" {
				display += fmt.Sprintf(", mount=%s", mp)
			}
			if ft != "" {
				display += fmt.Sprintf(", fstype=%s", ft)
			}
			response.DisplayParams = &display
			return response
		},
	})
}
