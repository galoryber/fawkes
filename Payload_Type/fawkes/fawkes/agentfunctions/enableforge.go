package agentfunctions

import (
	"encoding/json"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
	"github.com/MythicMeta/MythicContainer/logging"
	"github.com/MythicMeta/MythicContainer/mythicrpc"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "enable-forge",
		Description:         "Automatically register Fawkes with Forge Command Augmentation",
		HelpString:          "enable-forge",
		Version:             1,
		MitreAttackMappings: []string{},
		SupportedUIFeatures: []string{},
		Author:              "@galoryber",
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_WINDOWS},
		},
		CommandParameters: []agentstructs.CommandParameter{},
		TaskFunctionParseArgString: func(args *agentstructs.PTTaskMessageArgsData, input string) error {
			// No parameters for this command
			return nil
		},
		TaskFunctionParseArgDictionary: func(args *agentstructs.PTTaskMessageArgsData, input map[string]interface{}) error {
			// No parameters for this command
			return nil
		},
		TaskFunctionCreateTasking: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  taskData.Task.ID,
			}

			// First, add the forge_support command to this callback
			addCmdResp, err := mythicrpc.SendMythicRPCCallbackAddCommand(mythicrpc.MythicRPCCallbackAddCommandMessage{
				TaskID:   taskData.Task.ID,
				Commands: []string{"forge_support"},
			})

			if err != nil {
				logging.LogError(err, "Failed to add forge_support command to callback")
				response.Success = false
				response.Error = "Failed to add forge_support command: " + err.Error()
				return response
			}

			if !addCmdResp.Success {
				logging.LogError(nil, "forge_support command add failed", "error", addCmdResp.Error)
				response.Success = false
				response.Error = "Failed to add forge_support command: " + addCmdResp.Error
				return response
			}

			// Create the parameters for forge_support as a JSON string
			forgeParams := map[string]interface{}{
				"agent":                                    "fawkes",
				"bof_command":                              "inline-execute",
				"bof_file_parameter_name":                  "bof_file",
				"bof_argument_array_parameter_name":        "coff_arguments",
				"bof_entrypoint_parameter_name":            "function_name",
				"inline_assembly_command":                  "inlineassembly",
				"inline_assembly_file_parameter_name":      "assembly_file",
				"inline_assembly_argument_parameter_name":  "assembly_arguments",
				"execute_assembly_command":                 "",
				"execute_assembly_file_parameter_name":     "",
				"execute_assembly_argument_parameter_name": "",
			}

			// Marshal to JSON string
			paramsJSON, err := json.Marshal(forgeParams)
			if err != nil {
				logging.LogError(err, "Failed to marshal forge_support parameters")
				response.Success = false
				response.Error = "Failed to create forge_support parameters: " + err.Error()
				return response
			}

			// Create a subtask to call forge_support
			subtaskResp, err := mythicrpc.SendMythicRPCTaskCreateSubtask(mythicrpc.MythicRPCTaskCreateSubtaskMessage{
				TaskID:      taskData.Task.ID,
				CommandName: "forge_support",
				Params:      string(paramsJSON),
			})

			if err != nil {
				logging.LogError(err, "Failed to create forge_support subtask")
				response.Success = false
				response.Error = "Failed to create forge_support subtask: " + err.Error()
				return response
			}

			if !subtaskResp.Success {
				logging.LogError(nil, "forge_support subtask creation failed", "error", subtaskResp.Error)
				response.Success = false
				response.Error = "Failed to create forge_support subtask: " + subtaskResp.Error
				return response
			}

			// Mark as completed and provide user feedback
			completed := true
			response.Completed = &completed
			
			displayParams := "Registering Fawkes with Forge Command Augmentation\n" +
				"BOF Command: inline-execute\n" +
				"Assembly Command: inlineassembly"
			response.DisplayParams = &displayParams

			return response
		},
	})
}
