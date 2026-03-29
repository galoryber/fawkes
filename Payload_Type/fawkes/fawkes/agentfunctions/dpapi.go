package agentfunctions

import (
	"fmt"
	"path/filepath"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name: "dpapi",
		AssociatedBrowserScript: &agentstructs.BrowserScript{
			ScriptPath: filepath.Join(".", "fawkes", "browserscripts", "dpapi_new.js"),
			Author:     "@galoryber",
		},
		Description:         "DPAPI blob decryption, master key enumeration, Wi-Fi password extraction, browser key extraction (T1555.003, T1555.005)",
		HelpString:          "dpapi -action <decrypt|masterkeys|chrome-key> [-blob <base64>] [-entropy <base64>]",
		Version:             1,
		SupportedUIFeatures: []string{},
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1555.003", "T1555.005"},
		ScriptOnlyCommand:   false,
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_WINDOWS},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:             "action",
				ModalDisplayName: "Action",
				CLIName:          "action",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:          []string{"decrypt", "masterkeys", "chrome-key"},
				Description:      "decrypt: decrypt DPAPI blob. masterkeys: list master key files. chrome-key: extract browser encryption key.",
				DefaultValue:     "decrypt",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "blob",
				ModalDisplayName: "DPAPI Blob (base64)",
				CLIName:          "blob",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Base64-encoded DPAPI blob to decrypt (for decrypt action)",
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "entropy",
				ModalDisplayName: "Optional Entropy (base64)",
				CLIName:          "entropy",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Optional additional entropy for DPAPI decryption (base64-encoded)",
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "path",
				ModalDisplayName: "Master Key Path",
				CLIName:          "path",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Custom path to search for master keys (for masterkeys action)",
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
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
		TaskFunctionOPSECPre: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTTaskOPSECPreTaskMessageResponse {
			action, _ := taskData.Args.GetStringArg("action")
			msg := fmt.Sprintf("OPSEC WARNING: DPAPI credential access (action: %s). ", action)
			switch action {
			case "decrypt":
				msg += "CryptUnprotectData calls are logged by EDR and may trigger credential access alerts (T1555.003)."
			case "masterkeys":
				msg += "Enumerating DPAPI master keys accesses %APPDATA%\\Microsoft\\Protect — a known credential theft indicator."
			case "wifi":
				msg += "Wi-Fi password extraction reads profile XML files and decrypts with DPAPI (T1555.005)."
			case "browser":
				msg += "Browser key extraction targets Chrome/Edge local state files — commonly monitored by EDR (T1555.003)."
			default:
				msg += "DPAPI operations access protected data and may trigger credential theft alerts."
			}
			return agentstructs.PTTTaskOPSECPreTaskMessageResponse{
				TaskID: taskData.Task.ID, Success: true,
				OpsecPreBlocked: false, OpsecPreMessage: msg,
				OpsecPreBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionCreateTasking: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  taskData.Task.ID,
			}
			action, _ := taskData.Args.GetStringArg("action")
			display := fmt.Sprintf("%s", action)
			response.DisplayParams = &display
			createArtifact(taskData.Task.ID, "API Call", fmt.Sprintf("DPAPI CryptUnprotectData — %s", action))
			return response
		},
	})
}
