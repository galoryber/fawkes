package agentfunctions

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

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
				Name:             "filename",
				ModalDisplayName: ".NET Assembly",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Description:      "The .NET assembly to execute from files already registered in Mythic",
				Choices:          []string{},
				DefaultValue:     "",
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
				DefaultValue:     nil,
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
		},
		TaskFunctionParseArgString: func(args *agentstructs.PTTaskMessageArgsData, input string) error {
			// For command line usage, we'd need to parse differently
			// For now, require JSON format
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

			var fileID string
			var filename string
			var fileContents []byte
			var err error

			// Determine which parameter group was used
			switch strings.ToLower(taskData.Task.ParameterGroupName) {
			case "default":
				// User selected an existing file from the dropdown by filename
				filename, err = taskData.Args.GetStringArg("filename")
				if err != nil {
					logging.LogError(err, "Failed to get filename")
					response.Success = false
					response.Error = "Failed to get assembly file: " + err.Error()
					return response
				}
				
				// Search for the file by filename
				search, err := mythicrpc.SendMythicRPCFileSearch(mythicrpc.MythicRPCFileSearchMessage{
					CallbackID:      taskData.Callback.ID,
					Filename:        filename,
					LimitByCallback: false,
					MaxResults:      -1,
				})
				if err != nil {
					logging.LogError(err, "Failed to search for file by name")
					response.Success = false
					response.Error = "Failed to search for file: " + err.Error()
					return response
				}
				if !search.Success {
					response.Success = false
					response.Error = search.Error
					return response
				}
				if len(search.Files) == 0 {
					response.Success = false
					response.Error = fmt.Sprintf("Failed to find file: %s", filename)
					return response
				}
				fileID = search.Files[0].AgentFileId
				
				// Get file contents directly (no file transfer to agent)
				getResp, err := mythicrpc.SendMythicRPCFileGetContent(mythicrpc.MythicRPCFileGetContentMessage{
					AgentFileID: fileID,
				})
				if err != nil {
					logging.LogError(err, "Failed to get file contents")
					response.Success = false
					response.Error = "Failed to get file contents: " + err.Error()
					return response
				}
				if !getResp.Success {
					response.Success = false
					response.Error = getResp.Error
					return response
				}
				fileContents = getResp.Content
				
			case "new file":
				// User uploaded a new file
				fileID, err = taskData.Args.GetStringArg("file")
				if err != nil {
					logging.LogError(err, "Failed to get file")
					response.Success = false
					response.Error = "Failed to get assembly file: " + err.Error()
					return response
				}
				
				// Get file details
				search, err := mythicrpc.SendMythicRPCFileSearch(mythicrpc.MythicRPCFileSearchMessage{
					AgentFileID: fileID,
				})
				if err != nil {
					logging.LogError(err, "Failed to search for file")
					response.Success = false
					response.Error = "Failed to search for file: " + err.Error()
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
				filename = search.Files[0].Filename
				
				// Get file contents directly (no file transfer to agent)
				getResp, err := mythicrpc.SendMythicRPCFileGetContent(mythicrpc.MythicRPCFileGetContentMessage{
					AgentFileID: fileID,
				})
				if err != nil {
					logging.LogError(err, "Failed to get file contents")
					response.Success = false
					response.Error = "Failed to get file contents: " + err.Error()
					return response
				}
				if !getResp.Success {
					response.Success = false
					response.Error = getResp.Error
					return response
				}
				fileContents = getResp.Content
				
			default:
				response.Success = false
				response.Error = fmt.Sprintf("Unknown parameter group: %s", taskData.Task.ParameterGroupName)
				return response
			}

			// Get the arguments parameter as string
			arguments := ""
			argVal, err := taskData.Args.GetStringArg("arguments")
			if err == nil {
				arguments = argVal
			}

			// Build the display parameters
			displayParams := fmt.Sprintf("Assembly: %s", filename)
			if arguments != "" {
				displayParams += fmt.Sprintf("\nArguments: %s", arguments)
			}
			response.DisplayParams = &displayParams

			// Build the actual parameters JSON that will be sent to the agent
			// Encode file contents as base64 to embed in JSON
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

			// Set the parameters as a JSON string
			taskData.Args.SetManualArgs(string(paramsJSON))

			return response
		},
	})
}
