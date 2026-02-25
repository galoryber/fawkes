package agentfunctions

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
	"github.com/MythicMeta/MythicContainer/logging"
	"github.com/MythicMeta/MythicContainer/mythicrpc"
)

// getFileList queries the Mythic server for files and returns a list of filenames
// This function is used as a DynamicQuery to populate dropdown lists
func getFileList(msg agentstructs.PTRPCDynamicQueryFunctionMessage) []string {
	var files []string

	search := mythicrpc.MythicRPCFileSearchMessage{
		CallbackID:          msg.Callback,
		LimitByCallback:     false,
		MaxResults:          -1,
		IsPayload:           false,
		IsDownloadFromAgent: false,
		IsScreenshot:        false,
	}

	resp, err := mythicrpc.SendMythicRPCFileSearch(search)
	if err != nil {
		logging.LogError(err, "Failed to search for files")
		return files
	}

	if resp.Error != "" {
		logging.LogError(nil, resp.Error)
		return files
	}

	for _, file := range resp.Files {
		files = append(files, file.Filename)
	}

	return files
}

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "inline-assembly",
		Description:         "Execute a .NET assembly in memory using the CLR",
		HelpString:          "inline-assembly",
		Version:             1,
		MitreAttackMappings: []string{"T1055.001", "T1620"}, // Process Injection: Dynamic-link Library Injection, Reflective Code Loading
		SupportedUIFeatures: []string{},
		Author:              "@galoryber",
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_WINDOWS},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:                 "filename",
				ModalDisplayName:     ".NET Assembly",
				ParameterType:        agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Description:          "The .NET assembly to execute from files already registered in Mythic",
				Choices:              []string{},
				DefaultValue:         "",
				DynamicQueryFunction: getFileList,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: true,
						GroupName:           "Default",
						UIModalPosition:     0,
					},
				},
			},
			{
				Name:             "file",
				ModalDisplayName: ".NET Assembly",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_FILE,
				Description:      "Upload a new .NET assembly to execute",
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: true,
						GroupName:           "New File",
						UIModalPosition:     0,
					},
				},
			},
			{
				Name:             "arguments",
				ModalDisplayName: "Assembly Arguments",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Command-line arguments to pass to the assembly (space-separated)",
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
						UIModalPosition:     1,
					},
					{
						ParameterIsRequired: false,
						GroupName:           "New File",
						UIModalPosition:     1,
					},
				},
			},
			// Forge-compatible parameters
			{
				Name:             "assembly_file",
				ModalDisplayName: "Assembly File (Forge)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_FILE,
				Description:      "Assembly file UUID from Forge (used by Forge Command Augmentation)",
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Forge",
						UIModalPosition:     0,
					},
				},
			},
			{
				Name:             "assembly_arguments",
				ModalDisplayName: "Assembly Arguments (Forge)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Assembly arguments from Forge (used by Forge Command Augmentation)",
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Forge",
						UIModalPosition:     1,
					},
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

			var filename string
			var fileContents []byte

			// Check if this is a Forge invocation
			forgeFileID, forgeErr := taskData.Args.GetStringArg("assembly_file")
			isForgeCall := (forgeErr == nil && forgeFileID != "")

			if isForgeCall {
				// Forge invocation - use Forge parameter names
				// Get file details
				search, err := mythicrpc.SendMythicRPCFileSearch(mythicrpc.MythicRPCFileSearchMessage{
					AgentFileID: forgeFileID,
				})
				if err != nil {
					logging.LogError(err, "Failed to search for file")
					response.Success = false
					response.Error = "Failed to search for file: " + err.Error()
					return response
				}
				if !search.Success {
					response.Success = false
					response.Error = "Failed to search for file: " + search.Error
					return response
				}
				if len(search.Files) == 0 {
					response.Success = false
					response.Error = "File not found"
					return response
				}

				filename = search.Files[0].Filename

				// Get file contents
				getResp, err := mythicrpc.SendMythicRPCFileGetContent(mythicrpc.MythicRPCFileGetContentMessage{
					AgentFileID: forgeFileID,
				})
				if err != nil {
					logging.LogError(err, "Failed to get file content")
					response.Success = false
					response.Error = "Failed to get file content: " + err.Error()
					return response
				}
				if !getResp.Success {
					response.Success = false
					response.Error = getResp.Error
					return response
				}
				fileContents = getResp.Content

			} else {
				// Normal invocation - resolve file by checking actual args
				var fErr error
				filename, fileContents, fErr = resolveFileContents(taskData)
				if fErr != nil {
					response.Success = false
					response.Error = fErr.Error()
					return response
				}
			}

			// Get arguments (support both Forge and normal parameter names)
			arguments := ""
			// Try Forge parameter name first
			argVal, err := taskData.Args.GetStringArg("assembly_arguments")
			if err == nil && argVal != "" {
				arguments = argVal
			} else {
				// Fall back to normal parameter name
				argVal, err = taskData.Args.GetStringArg("arguments")
				if err == nil {
					arguments = argVal
				}
			}

			// Build the display parameters
			displayParams := fmt.Sprintf("Assembly: %s", filename)
			if arguments != "" {
				displayParams += fmt.Sprintf("\nArguments: %s", arguments)
			}
			response.DisplayParams = &displayParams

			// Build the actual parameters JSON that will be sent to the agent
			params := map[string]interface{}{
				"assembly_b64": base64.StdEncoding.EncodeToString(fileContents),
				"arguments":    arguments,
			}

			paramsJSON, err := json.Marshal(params)
			if err != nil {
				logging.LogError(err, "Failed to marshal parameters")
				response.Success = false
				response.Error = "Failed to create task parameters: " + err.Error()
				return response
			}

			taskData.Args.SetManualArgs(string(paramsJSON))

			return response
		},
	})
}
