package agentfunctions

import (
	"fmt"
	"path/filepath"
	"strings"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "certstore",
		Description:         "Enumerate certificate stores to find code signing certs, client auth certs, and private keys. Windows: CurrentUser/LocalMachine CAPI stores. macOS: Keychain. Linux: /etc/ssl/certs, /etc/pki/tls/certs.",
		HelpString:          "certstore -action list [-store MY] [-filter substring]\ncertstore -action find -filter thumbprint_or_subject\ncertstore -action export -filter <thumbprint> [-format pem|pfx] [-password <pfx_pass>]\ncertstore -action delete -filter <thumbprint> -store <store_name>\ncertstore -action import -data <base64_cert> [-format pem|pfx] [-store MY] [-password <pfx_pass>]",
		Version:             2,
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1552.004", "T1649"},
		SupportedUIFeatures: []string{},
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_WINDOWS, agentstructs.SUPPORTED_OS_LINUX, agentstructs.SUPPORTED_OS_MACOS},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:          "action",
				CLIName:       "action",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:       []string{"list", "find", "export", "delete", "import"},
				DefaultValue:  "list",
				Description:   "Action: list (enumerate all), find (search), export (PEM/PFX), delete (remove by thumbprint), import (add cert)",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     1,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:          "store",
				CLIName:       "store",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:  "",
				Description:   "Certificate store to enumerate (default: all). Options: MY (Personal), ROOT (Trusted Root CAs), CA (Intermediate CAs), Trust, TrustedPeople",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     2,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:          "filter",
				CLIName:       "filter",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:  "",
				Description:   "Filter certificates by subject, issuer, thumbprint, or serial number (case-insensitive substring match)",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     3,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:          "format",
				CLIName:       "format",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:       []string{"pem", "pfx"},
				DefaultValue:  "pem",
				Description:   "Export/import format: pem (certificate only) or pfx (certificate + private key, password-protected)",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     4,
						GroupName:            "Default",
					},
				},
			},
			{
				Name:          "password",
				CLIName:       "password",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:  "",
				Description:   "Password for PFX export/import (required for PFX format)",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     5,
						GroupName:            "Default",
					},
				},
			},
			{
				Name:          "data",
				CLIName:       "data",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:  "",
				Description:   "Base64-encoded certificate data for import action",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     6,
						GroupName:            "Default",
					},
				},
			},
		},
		AssociatedBrowserScript: &agentstructs.BrowserScript{
			ScriptPath: filepath.Join(".", "fawkes", "browserscripts", "certstore_new.js"),
			Author:     "@galoryber",
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
			msg := fmt.Sprintf("OPSEC WARNING: Accessing certificate store, action: %s (T1552.004, T1649). Certificate and private key export is monitored by EDR. Exporting private keys may trigger security event logs (CAPI2).", action)
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
			filter, _ := taskData.Args.GetStringArg("filter")
			if filter != "" {
				display += fmt.Sprintf(", filter: %s", filter)
			}
			response.DisplayParams = &display
			return response
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
			switch action {
			case "list", "find":
				// Track discovered certificates with private keys as artifacts
				for _, line := range strings.Split(responseText, "\n") {
					trimmed := strings.TrimSpace(line)
					if strings.Contains(trimmed, "HasPrivateKey: true") || strings.Contains(trimmed, "has_private_key: true") {
						createArtifact(processResponse.TaskData.Task.ID, "File Discovery",
							fmt.Sprintf("[CertStore] Certificate with private key found"))
					}
				}
			case "export":
				if strings.Contains(responseText, "exported") || strings.Contains(responseText, "Export") {
					filter, _ := processResponse.TaskData.Args.GetStringArg("filter")
					createArtifact(processResponse.TaskData.Task.ID, "File Write",
						fmt.Sprintf("[CertStore] Certificate exported: %s", filter))
				}
			case "delete":
				if strings.Contains(responseText, "deleted") || strings.Contains(responseText, "Deleted") {
					filter, _ := processResponse.TaskData.Args.GetStringArg("filter")
					createArtifact(processResponse.TaskData.Task.ID, "File Write",
						fmt.Sprintf("[CertStore] Certificate deleted: %s", filter))
				}
			case "import":
				if strings.Contains(responseText, "imported") || strings.Contains(responseText, "Import") {
					store, _ := processResponse.TaskData.Args.GetStringArg("store")
					createArtifact(processResponse.TaskData.Task.ID, "File Write",
						fmt.Sprintf("[CertStore] Certificate imported to store: %s", store))
				}
			}
			return response
		},
	})
}
