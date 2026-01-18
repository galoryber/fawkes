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
		Description:         "Display Forge registration information for Fawkes",
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

			// Create the registration info
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

			// Marshal to pretty JSON
			paramsJSON, err := json.MarshalIndent(forgeParams, "", "  ")
			if err != nil {
				logging.LogError(err, "Failed to marshal forge registration parameters")
				response.Success = false
				response.Error = "Failed to create forge registration info: " + err.Error()
				return response
			}

			// Mark as completed and provide the registration info
			completed := true
			response.Completed = &completed

			displayParams := "Forge Registration Information for Fawkes"
			response.DisplayParams = &displayParams

			output := "To register Fawkes with Forge Command Augmentation:\n\n" +
				"1. Load Forge commands into this callback:\n" +
				"   - In Mythic UI, go to this callback's page\n" +
				"   - Click 'Load Commands' and select the Forge container\n" +
				"   - Add the forge_support command\n\n" +
				"2. Run the forge_support command with these parameters:\n\n" +
				string(paramsJSON) + "\n\n" +
				"3. Once registered, you can use:\n" +
				"   - forge_collections -collectionName SliverArmory\n" +
				"   - forge_register -collectionName SliverArmory -commandName whoami\n" +
				"   - forge_bof_sa_whoami\n" +
				"   - forge_collections -collectionName SharpCollection\n" +
				"   - forge_register -collectionName SharpCollection -commandName Rubeus\n" +
				"   - forge_net_Rubeus -args \"dump\""

			// Create output response using MythicRPC
			_, err = mythicrpc.SendMythicRPCResponseCreate(mythicrpc.MythicRPCResponseCreateMessage{
				TaskID:   taskData.Task.ID,
				Response: []byte(output),
			})
			if err != nil {
				logging.LogError(err, "Failed to send response")
			}

			return response
		},
	})
}
