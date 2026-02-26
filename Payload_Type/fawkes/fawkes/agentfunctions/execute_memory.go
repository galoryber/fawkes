package agentfunctions

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
	"github.com/MythicMeta/MythicContainer/mythicrpc"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "execute-memory",
		Description:         "Execute an ELF binary entirely from memory using memfd_create. No file is written to disk — the binary exists only in an anonymous memory-backed file descriptor. Linux only.",
		HelpString:          "execute-memory -arguments 'arg1 arg2' -timeout 60",
		Version:             1,
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1620"}, // Reflective Code Loading
		SupportedUIFeatures: []string{},
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_LINUX},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:                 "filename",
				ModalDisplayName:     "ELF Binary",
				ParameterType:        agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Description:          "Select an ELF binary already registered in Mythic",
				Choices:              []string{},
				DefaultValue:         "",
				DynamicQueryFunction: getFileList,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: true,
						GroupName:           "Default",
						UIModalPosition:     1,
					},
				},
			},
			{
				Name:             "file",
				ModalDisplayName: "ELF Binary",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_FILE,
				Description:      "Upload a new ELF binary",
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: true,
						GroupName:           "New File",
						UIModalPosition:     1,
					},
				},
			},
			{
				Name:             "binary_b64",
				CLIName:          "binary_b64",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Base64-encoded ELF binary (for API/CLI usage)",
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: true,
						GroupName:           "CLI",
						UIModalPosition:     1,
					},
				},
			},
			{
				Name:             "arguments",
				CLIName:          "arguments",
				ModalDisplayName: "Arguments",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Command-line arguments to pass to the binary",
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
						UIModalPosition:     2,
					},
					{
						ParameterIsRequired: false,
						GroupName:           "New File",
						UIModalPosition:     2,
					},
					{
						ParameterIsRequired: false,
						GroupName:           "CLI",
						UIModalPosition:     2,
					},
				},
			},
			{
				Name:             "timeout",
				CLIName:          "timeout",
				ModalDisplayName: "Timeout (seconds)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				Description:      "Execution timeout in seconds (default: 60)",
				DefaultValue:     60,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
						UIModalPosition:     3,
					},
					{
						ParameterIsRequired: false,
						GroupName:           "New File",
						UIModalPosition:     3,
					},
					{
						ParameterIsRequired: false,
						GroupName:           "CLI",
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

			arguments, _ := taskData.Args.GetStringArg("arguments")
			timeout, _ := taskData.Args.GetNumberArg("timeout")
			if timeout <= 0 {
				timeout = 60
			}

			// Check for direct base64 binary first (CLI/API usage)
			b64, _ := taskData.Args.GetStringArg("binary_b64")
			if b64 != "" {
				decoded, err := base64.StdEncoding.DecodeString(b64)
				if err != nil {
					response.Success = false
					response.Error = "binary_b64 is not valid base64: " + err.Error()
					return response
				}
				params := map[string]interface{}{
					"binary_b64": b64,
					"arguments":  arguments,
					"timeout":    timeout,
				}
				paramsJSON, _ := json.Marshal(params)
				taskData.Args.SetManualArgs(string(paramsJSON))
				displayParams := fmt.Sprintf("ELF: base64 (%d bytes)", len(decoded))
				if arguments != "" {
					displayParams += fmt.Sprintf(", args: %s", arguments)
				}
				response.DisplayParams = &displayParams
				createArtifact(taskData.Task.ID, "Process Create", fmt.Sprintf("memfd_create + execve (%d bytes)", len(decoded)))
				return response
			}

			// File-based paths: get binary from Mythic file storage
			var filename string
			var fileContents []byte

			fileID, _ := taskData.Args.GetStringArg("file")
			if fileID != "" {
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
			} else {
				filename, _ = taskData.Args.GetStringArg("filename")
				if filename == "" {
					response.Success = false
					response.Error = "No binary provided (binary_b64, file upload, or filename selection required)"
					return response
				}
				search, err := mythicrpc.SendMythicRPCFileSearch(mythicrpc.MythicRPCFileSearchMessage{
					CallbackID:      taskData.Callback.ID,
					Filename:        filename,
					LimitByCallback: false,
					MaxResults:      -1,
				})
				if err != nil || !search.Success || len(search.Files) == 0 {
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
			}

			displayParams := fmt.Sprintf("ELF: %s (%d bytes)", filename, len(fileContents))
			if arguments != "" {
				displayParams += fmt.Sprintf(", args: %s", arguments)
			}
			response.DisplayParams = &displayParams
			createArtifact(taskData.Task.ID, "Process Create", fmt.Sprintf("memfd_create + execve: %s (%d bytes)", filename, len(fileContents)))

			params := map[string]interface{}{
				"binary_b64": base64.StdEncoding.EncodeToString(fileContents),
				"arguments":  arguments,
				"timeout":    timeout,
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
