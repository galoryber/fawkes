package agentfunctions

import (
	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
	"github.com/MythicMeta/MythicContainer/logging"
	"github.com/mitchellh/mapstructure"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "download",
		Description:         "Download a file from the target system",
		HelpString:          "download [path]",
		Version:             1,
		MitreAttackMappings: []string{"T1020", "T1030", "T1041"},
		SupportedUIFeatures: []string{"file_browser:download"},
		Author:              "@galoryber",
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_LINUX, agentstructs.SUPPORTED_OS_MACOS, agentstructs.SUPPORTED_OS_WINDOWS},
		},
		TaskFunctionCreateTasking: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  taskData.Task.ID,
			}
			if displayParams, err := taskData.Args.GetFinalArgs(); err != nil {
				logging.LogError(err, "Failed to get final arguments")
				response.Success = false
				response.Error = err.Error()
				return response
			} else {
				response.DisplayParams = &displayParams
			}
			return response
		},
		TaskFunctionParseArgDictionary: func(args *agentstructs.PTTaskMessageArgsData, input map[string]interface{}) error {
			// Support file browser integration
			fileBrowserData := agentstructs.FileBrowserTask{}
			if err := mapstructure.Decode(input, &fileBrowserData); err != nil {
				logging.LogError(err, "Failed to decode file browser data")
				return err
			} else {
				// Set the path from file browser selection
				args.SetManualArgs(fileBrowserData.FullPath)
				return nil
			}
		},
		TaskFunctionParseArgString: func(args *agentstructs.PTTaskMessageArgsData, input string) error {
			// For command line usage: download /path/to/file
			args.SetManualArgs(input)
			return nil
		},
	})
}
