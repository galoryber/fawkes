package agentfunctions

import (
	"fmt"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "ln",
		Description:         "Create symbolic or hard links — useful for symlink attacks, DLL side-loading, and file system manipulation.",
		HelpString:          "ln -target /etc/passwd -link /tmp/passwd_link -symbolic true\nln -target C:\\Windows\\System32\\calc.exe -link C:\\temp\\calc.exe\nln -target /tmp/old -link /tmp/new -symbolic true -force true",
		Version:             1,
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1036"},
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{
				agentstructs.SUPPORTED_OS_WINDOWS,
				agentstructs.SUPPORTED_OS_LINUX,
				agentstructs.SUPPORTED_OS_MACOS,
			},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:             "target",
				CLIName:          "target",
				ModalDisplayName: "Target Path",
				Description:      "Path to the existing file or directory",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: true, GroupName: "Default"},
				},
			},
			{
				Name:             "link",
				CLIName:          "link",
				ModalDisplayName: "Link Path",
				Description:      "Path for the new link to create",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: true, GroupName: "Default"},
				},
			},
			{
				Name:             "symbolic",
				CLIName:          "symbolic",
				ModalDisplayName: "Symbolic Link",
				Description:      "Create a symbolic link instead of a hard link (default: false = hard link)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_BOOLEAN,
				DefaultValue:     false,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "force",
				CLIName:          "force",
				ModalDisplayName: "Force Overwrite",
				Description:      "Remove existing file/symlink at link path before creating",
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
			target, _ := taskData.Args.GetStringArg("target")
			link, _ := taskData.Args.GetStringArg("link")
			symbolic, _ := taskData.Args.GetBooleanArg("symbolic")
			linkType := "hard"
			if symbolic {
				linkType = "symlink"
			}
			display := fmt.Sprintf("%s: %s -> %s", linkType, link, target)
			response.DisplayParams = &display

			createArtifact(taskData.Task.ID, "File Create",
				fmt.Sprintf("ln -%s %s -> %s", linkType, link, target))

			return response
		},
	})
}
