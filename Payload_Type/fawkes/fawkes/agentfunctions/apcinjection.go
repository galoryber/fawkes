package agentfunctions

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
	"github.com/MythicMeta/MythicContainer/logging"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "apc-injection",
		Description:         "Perform QueueUserAPC injection into an alertable thread. Use 'ts' command to find alertable threads (Suspended/DelayExecution).",
		HelpString:          "apc-injection",
		Version:             1,
		MitreAttackMappings: []string{"T1055.004"}, // Process Injection: Asynchronous Procedure Call
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
				Name:             "shellcode_b64",
				ModalDisplayName: "Shellcode (Base64)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Base64-encoded shellcode (for CLI/API usage)",
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: true,
						GroupName:           "CLI",
						UIModalPosition:     0,
					},
				},
			},
			{
				Name:             "pid",
				ModalDisplayName: "Target PID",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				Description:      "The process ID containing the target thread",
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
					{
						ParameterIsRequired: true,
						GroupName:           "CLI",
						UIModalPosition:     1,
					},
				},
			},
			{
				Name:             "tid",
				ModalDisplayName: "Target Thread ID",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				Description:      "The thread ID to queue the APC to (use 'ts' command to find alertable threads)",
				DefaultValue:     0,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: true,
						GroupName:           "Default",
						UIModalPosition:     2,
					},
					{
						ParameterIsRequired: true,
						GroupName:           "New File",
						UIModalPosition:     2,
					},
					{
						ParameterIsRequired: true,
						GroupName:           "CLI",
						UIModalPosition:     2,
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

			// Check for CLI group (shellcode_b64 provided directly)
			var shellcodeB64 string
			var filename string

			scB64, _ := taskData.Args.GetStringArg("shellcode_b64")
			if scB64 != "" {
				shellcodeB64 = scB64
				filename = "cli-shellcode"
			} else {
				var fileContents []byte
				var err error
				filename, fileContents, err = resolveFileContents(taskData)
				if err != nil {
					response.Success = false
					response.Error = err.Error()
					return response
				}
				shellcodeB64 = base64.StdEncoding.EncodeToString(fileContents)
			}

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

			tid, err := taskData.Args.GetNumberArg("tid")
			if err != nil {
				logging.LogError(err, "Failed to get TID")
				response.Success = false
				response.Error = "Failed to get target Thread ID: " + err.Error()
				return response
			}
			if tid <= 0 {
				response.Success = false
				response.Error = "Invalid Thread ID specified (must be greater than 0)"
				return response
			}

			displayParams := fmt.Sprintf("Shellcode: %s\nTarget PID: %d\nTarget TID: %d", filename, int(pid), int(tid))
			response.DisplayParams = &displayParams
			createArtifact(taskData.Task.ID, "Process Inject", fmt.Sprintf("APC injection into PID %d TID %d", int(pid), int(tid)))

			params := map[string]interface{}{
				"shellcode_b64": shellcodeB64,
				"pid":           int(pid),
				"tid":           int(tid),
			}
			paramsJSON, err := json.Marshal(params)
			if err != nil {
				response.Success = false
				response.Error = "Failed to marshal parameters: " + err.Error()
				return response
			}
			taskData.Args.SetManualArgs(string(paramsJSON))
			return response
		},
	})
}
