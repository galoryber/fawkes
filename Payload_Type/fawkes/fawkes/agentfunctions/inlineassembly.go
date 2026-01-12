package agentfunctions

import (
	"encoding/json"
	"fmt"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
	"github.com/MythicMeta/MythicContainer/logging"
	"github.com/MythicMeta/MythicContainer/mythicrpc"
)

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
				Name:             "file_id",
				ModalDisplayName: ".NET Assembly",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_FILE,
				Description:      "Select a .NET assembly from your computer or from files already uploaded to Mythic",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: true,
						UIModalPosition:     1,
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
						UIModalPosition:     2,
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

			// Get the file_id parameter
			fileID, err := taskData.Args.GetFileArg("file_id")
			if err != nil {
				logging.LogError(err, "Failed to get file_id")
				response.Success = false
				response.Error = "Failed to get assembly file: " + err.Error()
				return response
			}

			// Get file details from Mythic
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

			// Get the arguments parameter as string
			arguments := ""
			argVal, err := taskData.Args.GetStringArg("arguments")
			if err == nil {
				arguments = argVal
			}

			// Build the display parameters
			displayParams := fmt.Sprintf("Assembly: %s", search.Files[0].Filename)
			if arguments != "" {
				displayParams += fmt.Sprintf("\nArguments: %s", arguments)
			}
			response.DisplayParams = &displayParams

			// Build the actual parameters JSON that will be sent to the agent
			params := map[string]interface{}{
				"file_id":   fileID,
				"arguments": arguments,
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
