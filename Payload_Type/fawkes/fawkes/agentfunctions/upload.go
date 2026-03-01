package agentfunctions

import (
	"fmt"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
	"github.com/MythicMeta/MythicContainer/logging"
	"github.com/MythicMeta/MythicContainer/mythicrpc"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "upload",
		Description:         "Upload a file to the target system",
		HelpString:          "upload",
		Version:             1,
		MitreAttackMappings: []string{"T1020", "T1030", "T1041", "T1105"},
		SupportedUIFeatures: []string{"file_browser:upload"},
		Author:              "@galoryber",
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_LINUX, agentstructs.SUPPORTED_OS_MACOS, agentstructs.SUPPORTED_OS_WINDOWS},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:             "file_id",
				ModalDisplayName: "File to Upload",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_FILE,
				Description:      "Select a file from your computer or a file already uploaded to Mythic",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: true,
						UIModalPosition:     1,
					},
				},
			},
			{
				Name:             "remote_path",
				ModalDisplayName: "Remote Path",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Full path where the file will be written on the target",
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     2,
					},
				},
			},
			{
				Name:             "overwrite",
				ModalDisplayName: "Overwrite Existing File",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_BOOLEAN,
				Description:      "Overwrite the file if it already exists",
				DefaultValue:     false,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     3,
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

			fileID, err := taskData.Args.GetFileArg("file_id")
			if err != nil {
				logging.LogError(err, "Failed to get file_id")
				response.Success = false
				response.Error = err.Error()
				return response
			}

			// Get file details from Mythic
			search, err := mythicrpc.SendMythicRPCFileSearch(mythicrpc.MythicRPCFileSearchMessage{
				AgentFileID: fileID,
			})
			if err != nil {
				response.Success = false
				response.Error = err.Error()
				return response
			}
			if !search.Success {
				response.Success = false
				response.Error = search.Error
				return response
			}
			if len(search.Files) == 0 {
				response.Success = false
				response.Error = "Failed to find the specified file"
				return response
			}

			remotePath, err := taskData.Args.GetStringArg("remote_path")
			if err != nil {
				logging.LogError(err, "Failed to get remote_path")
				response.Success = false
				response.Error = err.Error()
				return response
			}

			// If no remote path specified, use just the filename
			var dest string
			if len(remotePath) == 0 {
				taskData.Args.SetArgValue("remote_path", search.Files[0].Filename)
				dest = search.Files[0].Filename
			} else {
				dest = remotePath
			}
			response.DisplayParams = &dest
			createArtifact(taskData.Task.ID, "File Write", fmt.Sprintf("Upload %s to %s", search.Files[0].Filename, dest))

			return response
		},
	})
}
