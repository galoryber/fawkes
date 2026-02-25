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
		Name:                "execute-shellcode",
		Description:         "Execute shellcode in the current process via VirtualAlloc + CreateThread. Shellcode runs in a new thread without cross-process injection.",
		HelpString:          "execute-shellcode",
		Version:             1,
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1059.006", "T1055.012"}, // Command and Scripting Interpreter, Process Hollowing
		SupportedUIFeatures: []string{},
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_WINDOWS},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:                 "filename",
				ModalDisplayName:     "Shellcode File",
				ParameterType:        agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Description:          "Select a shellcode file already registered in Mythic",
				Choices:              []string{},
				DefaultValue:         "",
				DynamicQueryFunction: getFileList,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: true,
						GroupName:            "Default",
						UIModalPosition:     1,
					},
				},
			},
			{
				Name:             "file",
				ModalDisplayName: "Shellcode File",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_FILE,
				Description:      "Upload a new shellcode file",
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: true,
						GroupName:            "New File",
						UIModalPosition:     1,
					},
				},
			},
			{
				Name:             "shellcode_b64",
				CLIName:          "shellcode_b64",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Base64-encoded shellcode (for API/CLI usage)",
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: true,
						GroupName:            "CLI",
						UIModalPosition:     1,
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

			var filename string
			var fileContents []byte

			switch strings.ToLower(taskData.Task.ParameterGroupName) {
			case "default":
				filename, _ = taskData.Args.GetStringArg("filename")
				search, err := mythicrpc.SendMythicRPCFileSearch(mythicrpc.MythicRPCFileSearchMessage{
					CallbackID:      taskData.Callback.ID,
					Filename:        filename,
					LimitByCallback: false,
					MaxResults:      -1,
				})
				if err != nil {
					logging.LogError(err, "Failed to search for file")
					response.Success = false
					response.Error = "Failed to search for file: " + err.Error()
					return response
				}
				if !search.Success || len(search.Files) == 0 {
					response.Success = false
					response.Error = fmt.Sprintf("File not found: %s", filename)
					return response
				}
				getResp, err := mythicrpc.SendMythicRPCFileGetContent(mythicrpc.MythicRPCFileGetContentMessage{
					AgentFileID: search.Files[0].AgentFileId,
				})
				if err != nil || !getResp.Success {
					response.Success = false
					response.Error = "Failed to get file contents"
					return response
				}
				fileContents = getResp.Content

			case "new file":
				fileID, _ := taskData.Args.GetStringArg("file")
				search, err := mythicrpc.SendMythicRPCFileSearch(mythicrpc.MythicRPCFileSearchMessage{
					AgentFileID: fileID,
				})
				if err != nil || !search.Success || len(search.Files) == 0 {
					response.Success = false
					response.Error = "Failed to find uploaded file"
					return response
				}
				filename = search.Files[0].Filename
				getResp, err := mythicrpc.SendMythicRPCFileGetContent(mythicrpc.MythicRPCFileGetContentMessage{
					AgentFileID: fileID,
				})
				if err != nil || !getResp.Success {
					response.Success = false
					response.Error = "Failed to get file contents"
					return response
				}
				fileContents = getResp.Content

			case "cli":
				sc, _ := taskData.Args.GetStringArg("shellcode_b64")
				if sc == "" {
					response.Success = false
					response.Error = "shellcode_b64 parameter is empty"
					return response
				}
				// Already base64, just pass through
				params := map[string]interface{}{"shellcode_b64": sc}
				paramsJSON, _ := json.Marshal(params)
				taskData.Args.SetManualArgs(string(paramsJSON))
				displayParams := fmt.Sprintf("Shellcode: base64 (%d chars)", len(sc))
				response.DisplayParams = &displayParams
				createArtifact(taskData.Task.ID, "API Call", "VirtualAlloc/CreateThread (self-injection)")
				return response

			default:
				response.Success = false
				response.Error = fmt.Sprintf("Unknown parameter group: %s", taskData.Task.ParameterGroupName)
				return response
			}

			displayParams := fmt.Sprintf("Shellcode: %s (%d bytes)", filename, len(fileContents))
			response.DisplayParams = &displayParams
			createArtifact(taskData.Task.ID, "API Call", fmt.Sprintf("VirtualAlloc/CreateThread self-injection (%d bytes)", len(fileContents)))

			params := map[string]interface{}{
				"shellcode_b64": base64.StdEncoding.EncodeToString(fileContents),
			}
			paramsJSON, err := json.Marshal(params)
			if err != nil {
				response.Success = false
				response.Error = "Failed to create task parameters"
				return response
			}
			taskData.Args.SetManualArgs(string(paramsJSON))

			return response
		},
	})
}
