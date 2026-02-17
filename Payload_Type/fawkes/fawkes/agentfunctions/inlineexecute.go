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

// getBOFFileList queries the Mythic server for BOF/COFF files and returns a list of filenames
func getBOFFileList(msg agentstructs.PTRPCDynamicQueryFunctionMessage) []string {
	search, err := mythicrpc.SendMythicRPCFileSearch(mythicrpc.MythicRPCFileSearchMessage{
		CallbackID:      msg.Callback,
		LimitByCallback: false,
		MaxResults:      -1,
	})
	if err != nil {
		logging.LogError(err, "Failed to search for BOF files")
		return []string{}
	}

	if !search.Success {
		logging.LogError(nil, "Failed to search for BOF files: "+search.Error)
		return []string{}
	}

	var fileList []string
	for _, file := range search.Files {
		// Filter for .o or .obj files (typical BOF extensions)
		if strings.HasSuffix(file.Filename, ".o") || strings.HasSuffix(file.Filename, ".obj") {
			fileList = append(fileList, file.Filename)
		}
	}

	if len(fileList) == 0 {
		return []string{"No BOF files found"}
	}

	return fileList
}

// convertTypedArrayToGoffloaderFormat converts Forge's TypedArray format to goffloader's string array format
// Input format: [["z", "hostname"], ["i", "80"], ["b", "AQIDBA=="]]
// Output format: ["zhostname", "i80", "bAQIDBA=="]
func convertTypedArrayToGoffloaderFormat(typedArray [][]string) ([]string, error) {
	var result []string
	for _, entry := range typedArray {
		if len(entry) < 2 {
			continue
		}
		argType := entry[0]
		argValue := entry[1]

		// Map Forge type names to our single-character type codes
		switch argType {
		case "z", "string":
			result = append(result, "z"+argValue)
		case "Z", "wchar":
			result = append(result, "Z"+argValue)
		case "i", "int", "int32":
			result = append(result, "i"+argValue)
		case "s", "short", "int16":
			result = append(result, "s"+argValue)
		case "b", "binary", "base64":
			result = append(result, "b"+argValue)
		default:
			return nil, fmt.Errorf("unknown argument type '%s' in TypedArray entry", argType)
		}
	}
	return result, nil
}

// convertToGoffloaderFormat converts our argument format to goffloader's string array format
// Input format: "z:hostname i:80 b:AQIDBA=="
// Output format: ["zhostname", "i80", "bAQIDBA=="]
func convertToGoffloaderFormat(argString string) ([]string, error) {
	if argString == "" {
		return []string{}, nil
	}

	var result []string
	argParts := strings.Fields(argString)

	for _, arg := range argParts {
		parts := strings.SplitN(arg, ":", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid argument format '%s', expected <type>:<value>", arg)
		}

		argType := parts[0]
		argValue := parts[1]

		// Strip surrounding quotes if present (e.g., z:"value" should become zvalue)
		if len(argValue) >= 2 && argValue[0] == '"' && argValue[len(argValue)-1] == '"' {
			argValue = argValue[1 : len(argValue)-1]
		}

		// Validate argument type
		switch argType {
		case "z", "Z", "i", "s", "b":
			// Special case: skip arguments marked as SKIP or NULL
			if strings.EqualFold(argValue, "SKIP") || strings.EqualFold(argValue, "NULL") {
				// Omit this argument entirely - don't add to result
				continue
			}
			// Special case: for empty string values, use a single space
			// go-coff won't accept empty strings, so use minimal valid placeholder
			if argValue == "" && (argType == "z" || argType == "Z") {
				argValue = " "
			}
			// Valid types - go-coff expects format like "zhostname" or "i80"
			result = append(result, argType+argValue)
		default:
			return nil, fmt.Errorf("unknown argument type '%s', valid types are: z (string), Z (wstring), i (int32), s (int16), b (binary base64)", argType)
		}
	}

	return result, nil
}

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "inline-execute",
		Description:         "Execute a Beacon Object File (BOF/COFF) in memory",
		HelpString:          "inline-execute",
		Version:             1,
		MitreAttackMappings: []string{"T1620"}, // Reflective Code Loading
		SupportedUIFeatures: []string{},
		Author:              "@galoryber",
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_WINDOWS},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:                 "filename",
				ModalDisplayName:     "BOF File",
				ParameterType:        agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Description:          "Select a BOF/COFF file already uploaded to Mythic",
				Choices:              []string{},
				DefaultValue:         "",
				DynamicQueryFunction: getBOFFileList,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: true,
						GroupName:           "Default",
						UIModalPosition:     0,
					},
				},
			},
			// Forge-compatible parameter names
			{
				Name:             "bof_file",
				ModalDisplayName: "BOF File (Forge)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_FILE,
				Description:      "BOF file UUID (used by Forge)",
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
				Name:             "file",
				ModalDisplayName: "BOF File",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_FILE,
				Description:      "Upload a new BOF/COFF file to execute",
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
				Name:             "entry_point",
				ModalDisplayName: "Entry Point",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Entry point function name (typically 'go')",
				DefaultValue:     "go",
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
			// Forge-compatible entry point parameter
			{
				Name:             "function_name",
				ModalDisplayName: "Function Name (Forge)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Entry point function name (used by Forge)",
				DefaultValue:     "go",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Forge",
						UIModalPosition:     1,
					},
				},
			},
			{
				Name:             "arguments",
				ModalDisplayName: "BOF Arguments",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Arguments in format: <type>:<value> separated by spaces\nTypes: z (string), Z (wstring), i (int32), s (int16), b (binary base64)\nExample: z:hostname i:80 b:AQIDBA==",
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
				},
			},
			// Forge-compatible arguments parameter (TypedArray format from Forge)
			{
				Name:             "coff_arguments",
				ModalDisplayName: "COFF Arguments (Forge)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_TYPED_ARRAY,
				Description:      "BOF arguments as TypedArray (used by Forge Command Augmentation)",
				DefaultValue:     [][]string{},
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Forge",
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

			var fileID string
			var filename string
			var fileContents []byte
			var err error

			// Check if this is a Forge invocation by looking for bof_file parameter
			forgeFileID, forgeErr := taskData.Args.GetStringArg("bof_file")
			isForgeCall := (forgeErr == nil && forgeFileID != "")

			if isForgeCall {
				// Forge invocation - use Forge parameter names
				fileID = forgeFileID

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
					AgentFileID: fileID,
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
				// Normal invocation - use existing parameter logic
				// Determine which parameter group was used
				switch strings.ToLower(taskData.Task.ParameterGroupName) {
				case "default":
				// User selected an existing file from the dropdown
				filename, err = taskData.Args.GetStringArg("filename")
				if err != nil {
					logging.LogError(err, "Failed to get filename")
					response.Success = false
					response.Error = "Failed to get BOF file: " + err.Error()
					return response
				}

				// Search for the file by filename
				search, err := mythicrpc.SendMythicRPCFileSearch(mythicrpc.MythicRPCFileSearchMessage{
					CallbackID:      taskData.Callback.ID,
					Filename:        filename,
					LimitByCallback: false,
					MaxResults:      1,
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
					response.Error = "File not found: " + filename
					return response
				}

				fileID = search.Files[0].AgentFileId

				// Get file contents
				getResp, err := mythicrpc.SendMythicRPCFileGetContent(mythicrpc.MythicRPCFileGetContentMessage{
					AgentFileID: fileID,
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

			case "new file":
				// User uploaded a new file
				fileID, err = taskData.Args.GetStringArg("file")
				if err != nil {
					logging.LogError(err, "Failed to get file")
					response.Success = false
					response.Error = "Failed to get BOF file: " + err.Error()
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
					AgentFileID: fileID,
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

			default:
				response.Success = false
				response.Error = fmt.Sprintf("Unknown parameter group: %s", taskData.Task.ParameterGroupName)
				return response
				}
			}

			// Get entry point and arguments (support both Forge and normal parameter names)
			var goffloaderArgs []string
			entryPoint := "go"

			if isForgeCall {
				// Forge path: use function_name for entry point and coff_arguments (TypedArray) for args
				fnVal, fnErr := taskData.Args.GetStringArg("function_name")
				if fnErr == nil && fnVal != "" {
					entryPoint = fnVal
				}

				// Get Forge TypedArray arguments
				typedArgs, taErr := taskData.Args.GetTypedArrayArg("coff_arguments")
				if taErr == nil && len(typedArgs) > 0 {
					goffloaderArgs, err = convertTypedArrayToGoffloaderFormat(typedArgs)
					if err != nil {
						logging.LogError(err, "Failed to convert Forge TypedArray arguments")
						response.Success = false
						response.Error = "Failed to convert Forge arguments: " + err.Error()
						return response
					}
				}
			} else {
				// Normal path: use entry_point and arguments string
				entryVal, epErr := taskData.Args.GetStringArg("entry_point")
				if epErr == nil && entryVal != "" {
					entryPoint = entryVal
				}

				arguments := ""
				argVal, argErr := taskData.Args.GetStringArg("arguments")
				if argErr == nil {
					arguments = argVal
				}

				// Convert arguments to goffloader format
				goffloaderArgs, err = convertToGoffloaderFormat(arguments)
				if err != nil {
					logging.LogError(err, "Failed to convert BOF arguments")
					response.Success = false
					response.Error = "Failed to convert arguments: " + err.Error()
					return response
				}
			}

			// Build the display parameters
			displayParams := fmt.Sprintf("BOF: %s, Entry: %s", filename, entryPoint)
			if len(goffloaderArgs) > 0 {
				displayParams += fmt.Sprintf("\nArguments: %v", goffloaderArgs)
			}
			response.DisplayParams = &displayParams

			// Build the actual parameters JSON that will be sent to the agent
			params := map[string]interface{}{
				"bof_b64":     base64.StdEncoding.EncodeToString(fileContents),
				"entry_point": entryPoint,
				"arguments":   goffloaderArgs,
			}

			paramsJSON, err := json.Marshal(params)
			if err != nil {
				logging.LogError(err, "Failed to marshal parameters")
				response.Success = false
				response.Error = "Failed to create task parameters: " + err.Error()
				return response
			}

			response.Success = true
			taskData.Args.SetManualArgs(string(paramsJSON))

			return response
		},
	})
}
