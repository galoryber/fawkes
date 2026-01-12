package agentfunctions

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strconv"
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

// packBOFArguments packs arguments according to the Beacon/goffloader format
// Argument format: <type>:<value> where type is z (string), i (int32), s (int16), b (binary base64)
// Example: "z:hostname i:80 b:AQIDBA=="
func packBOFArguments(argString string) ([]byte, error) {
	if argString == "" {
		// No arguments - return minimal packed format
		buf := make([]byte, 8)
		binary.LittleEndian.PutUint32(buf[0:4], 0) // total size = 0
		binary.LittleEndian.PutUint32(buf[4:8], 0) // arg count = 0
		return buf, nil
	}

	argBuffer := &strings.Builder{}
	argParts := strings.Fields(argString)
	argCount := 0

	for _, arg := range argParts {
		parts := strings.SplitN(arg, ":", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid argument format '%s', expected <type>:<value>", arg)
		}

		argType := parts[0]
		argValue := parts[1]

		switch argType {
		case "z": // null-terminated string
			size := len(argValue) + 1 // +1 for null terminator
			sizeBytes := make([]byte, 4)
			binary.LittleEndian.PutUint32(sizeBytes, uint32(size))
			argBuffer.Write(sizeBytes)
			argBuffer.WriteString(argValue)
			argBuffer.WriteByte(0) // null terminator
			argCount++

		case "Z": // null-terminated wide string (UTF-16LE)
			// Convert to UTF-16LE
			wstr := utf16Encode(argValue)
			size := (len(wstr) + 1) * 2 // +1 for null terminator, *2 for wide chars
			sizeBytes := make([]byte, 4)
			binary.LittleEndian.PutUint32(sizeBytes, uint32(size))
			argBuffer.Write(sizeBytes)
			for _, w := range wstr {
				wBytes := make([]byte, 2)
				binary.LittleEndian.PutUint16(wBytes, w)
				argBuffer.Write(wBytes)
			}
			// null terminator for wide string
			argBuffer.Write([]byte{0, 0})
			argCount++

		case "i": // int32
			val, err := strconv.ParseInt(argValue, 0, 32)
			if err != nil {
				return nil, fmt.Errorf("invalid int32 value '%s': %v", argValue, err)
			}
			sizeBytes := make([]byte, 4)
			binary.LittleEndian.PutUint32(sizeBytes, 4)
			argBuffer.Write(sizeBytes)
			valBytes := make([]byte, 4)
			binary.LittleEndian.PutUint32(valBytes, uint32(val))
			argBuffer.Write(valBytes)
			argCount++

		case "s": // int16
			val, err := strconv.ParseInt(argValue, 0, 16)
			if err != nil {
				return nil, fmt.Errorf("invalid int16 value '%s': %v", argValue, err)
			}
			sizeBytes := make([]byte, 4)
			binary.LittleEndian.PutUint32(sizeBytes, 2)
			argBuffer.Write(sizeBytes)
			valBytes := make([]byte, 2)
			binary.LittleEndian.PutUint16(valBytes, uint16(val))
			argBuffer.Write(valBytes)
			argCount++

		case "b": // binary data (base64 encoded)
			data, err := base64.StdEncoding.DecodeString(argValue)
			if err != nil {
				return nil, fmt.Errorf("invalid base64 data '%s': %v", argValue, err)
			}
			sizeBytes := make([]byte, 4)
			binary.LittleEndian.PutUint32(sizeBytes, uint32(len(data)))
			argBuffer.Write(sizeBytes)
			argBuffer.Write(data)
			argCount++

		default:
			return nil, fmt.Errorf("unknown argument type '%s', valid types are: z (string), Z (wstring), i (int32), s (int16), b (binary)", argType)
		}
	}

	// Build final packed format: [total_size][arg_count][arg_data]
	argData := []byte(argBuffer.String())
	result := make([]byte, 8+len(argData))
	binary.LittleEndian.PutUint32(result[0:4], uint32(len(argData)))
	binary.LittleEndian.PutUint32(result[4:8], uint32(argCount))
	copy(result[8:], argData)

	return result, nil
}

// utf16Encode converts a string to UTF-16LE encoding
func utf16Encode(s string) []uint16 {
	runes := []rune(s)
	result := make([]uint16, 0, len(runes))
	for _, r := range runes {
		if r <= 0xFFFF {
			result = append(result, uint16(r))
		} else {
			// Encode as surrogate pair for characters outside BMP
			r -= 0x10000
			result = append(result, uint16((r>>10)+0xD800))
			result = append(result, uint16((r&0x3FF)+0xDC00))
		}
	}
	return result
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
			{
				Name:             "file",
				ModalDisplayName: "BOF File",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_FILE,
				Description:      "Upload a new BOF/COFF file to execute",
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

			// Get entry point and arguments
			entryPoint := "go"
			entryVal, err := taskData.Args.GetStringArg("entry_point")
			if err == nil && entryVal != "" {
				entryPoint = entryVal
			}

			arguments := ""
			argVal, err := taskData.Args.GetStringArg("arguments")
			if err == nil {
				arguments = argVal
			}

			// Pack the arguments according to BOF format
			packedArgs, err := packBOFArguments(arguments)
			if err != nil {
				logging.LogError(err, "Failed to pack BOF arguments")
				response.Success = false
				response.Error = "Failed to pack arguments: " + err.Error()
				return response
			}

			// Build the display parameters
			displayParams := fmt.Sprintf("BOF: %s, Entry: %s", filename, entryPoint)
			if arguments != "" {
				displayParams += fmt.Sprintf("\nArguments: %s", arguments)
			}
			response.DisplayParams = &displayParams

			// Build the actual parameters JSON that will be sent to the agent
			params := map[string]interface{}{
				"bof_b64":        base64.StdEncoding.EncodeToString(fileContents),
				"entry_point":    entryPoint,
				"packed_args_b64": base64.StdEncoding.EncodeToString(packedArgs),
			}

			paramsJSON, err := json.Marshal(params)
			if err != nil {
				logging.LogError(err, "Failed to marshal parameters")
				response.Success = false
				response.Error = "Failed to create task parameters: " + err.Error()
				return response
			}

			response.Success = true
			paramsStr := string(paramsJSON)
			taskData.Args.SetArgValues(paramsStr)

			return response
		},
	})
}
