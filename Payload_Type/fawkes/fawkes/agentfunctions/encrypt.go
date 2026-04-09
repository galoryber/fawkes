package agentfunctions

import (
	"fmt"
	"strings"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "encrypt",
		Description:         "Encrypt or decrypt files using AES-256-GCM. Single file, batch by glob pattern (encrypt-files), or reverse batch (decrypt-files). Purple team ransomware simulation (T1486).",
		HelpString:          "encrypt -action encrypt -path /tmp/data.tar.gz\nencrypt -action decrypt -path /tmp/data.tar.gz.enc -key <base64key>\nencrypt -action encrypt-files -path '/home/user/Documents/*.docx' -confirm SIMULATE\nencrypt -action decrypt-files -path /home/user/Documents -key <base64key>",
		Version:             2,
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1560.001", "T1486"},
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{
				agentstructs.SUPPORTED_OS_WINDOWS,
				agentstructs.SUPPORTED_OS_LINUX,
				agentstructs.SUPPORTED_OS_MACOS,
			},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:          "action",
				CLIName:       "action",
				Description:   "encrypt: single file. decrypt: single file. encrypt-files: batch by glob (ransomware sim T1486). decrypt-files: reverse batch in directory.",
				DefaultValue:  "encrypt",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:       []string{"encrypt", "decrypt", "encrypt-files", "decrypt-files"},
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: true, GroupName: "Default"},
				},
			},
			{
				Name:          "path",
				CLIName:       "path",
				Description:   "File path (encrypt/decrypt), glob pattern (encrypt-files, e.g. '/home/user/*.docx'), or directory (decrypt-files)",
				DefaultValue:  "",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: true, GroupName: "Default"},
				},
			},
			{
				Name:          "output",
				CLIName:       "output",
				Description:   "Output file path (single encrypt/decrypt only)",
				DefaultValue:  "",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:          "key",
				CLIName:       "key",
				Description:   "Base64-encoded AES-256 key (auto-generated for encrypt if not provided, required for decrypt/decrypt-files)",
				DefaultValue:  "",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "confirm",
				CLIName:          "confirm",
				ModalDisplayName: "Safety Confirmation",
				Description:      "Type SIMULATE to confirm batch encryption (encrypt-files safety gate). Prevents accidental mass encryption.",
				DefaultValue:     "",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "max_files",
				CLIName:          "max_files",
				ModalDisplayName: "Max Files",
				Description:      "Maximum files to encrypt in batch mode (default: 100, safety limit)",
				DefaultValue:     100,
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
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
			action, _ := taskData.Args.GetStringArg("action")
			path, _ := taskData.Args.GetStringArg("path")
			msg := fmt.Sprintf("OPSEC WARNING: File encryption (%s) on %s (T1560.001).", action, path)
			if action == "encrypt-files" {
				msg = fmt.Sprintf("CRITICAL OPSEC WARNING: Batch file encryption (T1486 Data Encrypted for Impact). Pattern: %s. This IS a ransomware simulation — EDR behavioral engines specifically detect rapid bulk file encryption+rename. Anti-ransomware canary files, volume shadow copy monitors, and MFT change rate alerts will fire. Only proceed if this is an authorized purple team exercise.", path)
			}
			return agentstructs.PTTTaskOPSECPreTaskMessageResponse{
				TaskID: taskData.Task.ID, Success: true,
				OpsecPreBlocked:    false,
				OpsecPreMessage:    msg,
				OpsecPreBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionProcessResponse: func(processResponse agentstructs.PtTaskProcessResponseMessage) agentstructs.PTTaskProcessResponseMessageResponse {
			response := agentstructs.PTTaskProcessResponseMessageResponse{
				TaskID:  processResponse.TaskData.Task.ID,
				Success: true,
			}
			responseText, ok := processResponse.Response.(string)
			if !ok || responseText == "" {
				return response
			}
			action, _ := processResponse.TaskData.Args.GetStringArg("action")
			if action == "encrypt-files" && strings.Contains(responseText, "encrypted") {
				tagTask(processResponse.TaskData.Task.ID, "IMPACT",
					"Ransomware simulation: batch file encryption (T1486)")
				logOperationEvent(processResponse.TaskData.Task.ID,
					"[IMPACT] Batch file encryption completed — ransomware simulation (T1486)", true)
			}
			if action == "decrypt-files" && strings.Contains(responseText, "decrypted") {
				logOperationEvent(processResponse.TaskData.Task.ID,
					"[RECOVERY] Batch file decryption — ransomware recovery simulation", false)
			}
			return response
		},
		TaskFunctionCreateTasking: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  taskData.Task.ID,
			}
			action, _ := taskData.Args.GetStringArg("action")
			path, _ := taskData.Args.GetStringArg("path")
			display := fmt.Sprintf("%s %s", action, path)
			response.DisplayParams = &display

			if action == "encrypt-files" {
				createArtifact(taskData.Task.ID, "Impact", fmt.Sprintf("Batch file encryption (T1486): %s", path))
				logOperationEvent(taskData.Task.ID,
					fmt.Sprintf("[IMPACT] Ransomware simulation started: encrypt-files %s", path), true)
			} else if action == "decrypt-files" {
				createArtifact(taskData.Task.ID, "Recovery", fmt.Sprintf("Batch file decryption: %s", path))
			} else {
				createArtifact(taskData.Task.ID, "File Write", fmt.Sprintf("File encryption of %s", path))
			}
			return response
		},
	})
}
