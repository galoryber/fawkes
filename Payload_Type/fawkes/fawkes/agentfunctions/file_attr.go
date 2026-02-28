package agentfunctions

import (
	"fmt"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "file-attr",
		Description:         "Get or set file attributes — hidden, readonly, immutable, system flags for file hiding and protection.",
		HelpString:          "file-attr -path C:\\temp\\payload.exe\nfile-attr -path C:\\temp\\file.exe -attrs \"+hidden,+system\"\nfile-attr -path /etc/cron.d/job -attrs \"+immutable\"\nfile-attr -path /tmp/file -attrs \"-nodump,+noatime\"",
		Version:             1,
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1564.001", "T1222"},
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
				ModalDisplayName: "File Path",
				Description:      "Path to the file to inspect or modify",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: true, GroupName: "Default"},
				},
			},
			{
				Name:             "attrs",
				CLIName:          "attrs",
				ModalDisplayName: "Attributes",
				Description:      "Comma-separated attribute changes: +hidden,-readonly,+immutable (omit to just view current attributes). Windows: hidden, readonly, system, archive, not_indexed. Linux: immutable, append, nodump, noatime, sync, nocow. macOS: hidden, immutable, append.",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:     "",
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
			attrs, _ := taskData.Args.GetStringArg("attrs")

			if attrs != "" {
				display := fmt.Sprintf("%s attrs=%s", path, attrs)
				response.DisplayParams = &display

				createArtifact(taskData.Task.ID, "File Modify",
					fmt.Sprintf("file-attr set %s %s", path, attrs))
			} else {
				display := fmt.Sprintf("%s", path)
				response.DisplayParams = &display
			}

			return response
		},
	})
}
