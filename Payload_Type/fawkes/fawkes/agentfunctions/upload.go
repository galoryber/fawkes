package agentfunctions

import (
	"fmt"
	"path/filepath"
	"strings"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
	"github.com/MythicMeta/MythicContainer/logging"
	"github.com/MythicMeta/MythicContainer/mythicrpc"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "upload",
		AssociatedBrowserScript: &agentstructs.BrowserScript{
			ScriptPath: filepath.Join(".", "fawkes", "browserscripts", "upload_new.js"),
			Author:     "@galoryber",
		},
		Description:         "Upload a file to the target system (optional auto-decompression for gzip files)",
		HelpString:          "upload — supports auto-decompression of gzip files with decompress parameter",
		Version:             2,
		MitreAttackMappings: []string{"T1020", "T1030", "T1041", "T1105"},
		SupportedUIFeatures: []string{"file_browser:upload"},
		Author:              "@galoryber",
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS:        []string{agentstructs.SUPPORTED_OS_LINUX, agentstructs.SUPPORTED_OS_MACOS, agentstructs.SUPPORTED_OS_WINDOWS},
			CommandIsSuggested: true,
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
			{
				Name:             "decompress",
				ModalDisplayName: "Auto-Decompress (gzip)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_BOOLEAN,
				Description:      "Automatically decompress gzip-compressed files after transfer. Use with compressed downloads for bandwidth-efficient round-trip.",
				DefaultValue:     false,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     4,
					},
				},
			},
		},
		TaskFunctionOPSECPost: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskOPSECPostTaskMessageResponse {
			return agentstructs.PTTaskOPSECPostTaskMessageResponse{
				TaskID:              taskData.Task.ID,
				Success:             true,
				OpsecPostBlocked:    false,
				OpsecPostMessage:    "OPSEC AUDIT: File upload completed. File write to target creates filesystem artifacts. Uploaded files should be cleaned up after use to minimize forensic evidence.",
				OpsecPostBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
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
			remotePath, _ := taskData.Args.GetStringArg("remote_path")
			msg := fmt.Sprintf("OPSEC WARNING: Uploading file to target path: %s (T1105). File writes trigger EDR scanning and may create forensic artifacts (MFT entries, USN journal). Writing to sensitive directories increases detection risk.", remotePath)
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
		TaskFunctionProcessResponse: func(processResponse agentstructs.PtTaskProcessResponseMessage) agentstructs.PTTaskProcessResponseMessageResponse {
			response := agentstructs.PTTaskProcessResponseMessageResponse{
				TaskID:  processResponse.TaskData.Task.ID,
				Success: true,
			}
			responseText, ok := processResponse.Response.(string)
			if !ok || responseText == "" {
				return response
			}
			if strings.Contains(responseText, "success") || strings.Contains(responseText, "Success") || strings.Contains(responseText, "uploaded") || strings.Contains(responseText, "wrote") {
				remotePath, _ := processResponse.TaskData.Args.GetStringArg("remote_path")
				createArtifact(processResponse.TaskData.Task.ID, "File Write", fmt.Sprintf("[upload] Wrote file to %s", remotePath))
			}
			return response
		},
	})
}
