package agentfunctions

import (
	"fmt"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "shell-config",
		Description:         "Read shell history, list/read/inject/remove/clear shell config files for persistence and anti-forensics. Unix: bashrc/zshrc (T1546.004, T1552.003, T1070.003). Windows: PowerShell profiles and PSReadLine history (T1546.013, T1552.003, T1070.003).",
		HelpString:          "shell-config -action <history|list|read|inject|remove|clear> [-file <.bashrc>] [-line <command>] [-user <username>] [-lines <count>]",
		Version:             4,
		SupportedUIFeatures: []string{},
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1546.004", "T1546.013", "T1552.003", "T1070.003"},
		ScriptOnlyCommand:   false,
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_LINUX, agentstructs.SUPPORTED_OS_MACOS, agentstructs.SUPPORTED_OS_WINDOWS},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:             "action",
				ModalDisplayName: "Action",
				CLIName:          "action",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:          []string{"history", "list", "read", "inject", "remove", "clear"},
				Description:      "Action: history (read shell history), list (enumerate config files), read (view file), inject (append line), remove (delete line), clear (wipe history files)",
				DefaultValue:     "list",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: true,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "file",
				ModalDisplayName: "File",
				CLIName:          "file",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Target file (e.g., .bashrc, .zshrc, /etc/profile). Relative paths resolve to home dir.",
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "line",
				ModalDisplayName: "Line",
				CLIName:          "line",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Command line to inject or remove",
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
				Description:      "Target user (default: current user)",
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "lines",
				ModalDisplayName: "Lines",
				CLIName:          "lines",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				Description:      "Number of history lines to show (default 100)",
				DefaultValue:     100,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "comment",
				ModalDisplayName: "Comment",
				CLIName:          "comment",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Optional comment appended to injected line (for tracking/cleanup)",
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
		TaskFunctionOPSECPre: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTTaskOPSECPreTaskMessageResponse {
			actionVal, _ := taskData.Args.GetStringArg("action")
			msg := fmt.Sprintf("OPSEC WARNING: Shell configuration operation, action: %s (T1546.004). Modifying shell profiles (.bashrc, .zshrc, .profile) is a persistence technique. File integrity monitoring watches these files.", actionVal)
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
			file, _ := taskData.Args.GetStringArg("file")

			display := fmt.Sprintf("%s", action)
			response.DisplayParams = &display

			// Report artifacts for inject/remove/clear actions
			if action == "inject" || action == "remove" || action == "clear" {
				artifactFile := file
				if artifactFile == "" {
					artifactFile = "(shell config file)"
				}
				artifactAction := "File Modify"
				if action == "inject" {
					artifactAction = "File Modify"
				}
				createArtifact(taskData.Task.ID, artifactAction, artifactFile)
			}

			return response
		},
	})
}
