package agentfunctions

import (
	"fmt"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "chmod",
		Description:         "Modify file and directory permissions (octal or symbolic notation). Supports recursive directory operations.",
		HelpString:          "chmod -path /tmp/payload -mode 755\nchmod -path ./script.sh -mode +x\nchmod -path /var/data -mode 644 -recursive true\nchmod -path /tmp -mode u+rwx,go+rx",
		Version:             1,
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1222"},
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{
				agentstructs.SUPPORTED_OS_WINDOWS,
				agentstructs.SUPPORTED_OS_LINUX,
				agentstructs.SUPPORTED_OS_MACOS,
			},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:             "path",
				CLIName:          "path",
				ModalDisplayName: "File or Directory Path",
				Description:      "Path to file or directory to modify",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: true, GroupName: "Default"},
				},
			},
			{
				Name:             "mode",
				CLIName:          "mode",
				ModalDisplayName: "Permissions",
				Description:      "Octal mode (755, 644) or symbolic notation (+x, u+rw, go-w, a=rx)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: true, GroupName: "Default"},
				},
			},
			{
				Name:             "recursive",
				CLIName:          "recursive",
				ModalDisplayName: "Recursive",
				Description:      "Apply permissions recursively to directory contents",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_BOOLEAN,
				DefaultValue:     false,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
		},
		TaskFunctionParseArgString: func(args *agentstructs.PTTaskMessageArgsData, input string) error {
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
			path, _ := taskData.Args.GetStringArg("path")
			mode, _ := taskData.Args.GetStringArg("mode")
			display := fmt.Sprintf("%s %s", mode, path)
			response.DisplayParams = &display
			createArtifact(taskData.Task.ID, "File Write", fmt.Sprintf("Permission change on %s", path))
			return response
		},
	})
}
