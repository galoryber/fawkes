package agentfunctions

import (
	"encoding/json"
	"fmt"
	"path/filepath"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "arp",
		Description:         "Display ARP table — shows IP-to-MAC address mappings for nearby hosts. Filter by IP, MAC, or interface.",
		HelpString:          "arp [-ip <subnet>] [-mac <prefix>] [-interface <name>]",
		Version:             2,
		MitreAttackMappings: []string{"T1016.001"},
		SupportedUIFeatures: []string{},
		Author:              "@galoryber",
		AssociatedBrowserScript: &agentstructs.BrowserScript{
			ScriptPath: filepath.Join(".", "fawkes", "browserscripts", "arp_new.js"),
			Author:     "@galoryber",
		},
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_LINUX, agentstructs.SUPPORTED_OS_MACOS, agentstructs.SUPPORTED_OS_WINDOWS},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:          "ip",
				CLIName:       "ip",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:  "",
				Description:   "Filter by IP address (substring match, e.g. '192.168')",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     1,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:          "mac",
				CLIName:       "mac",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:  "",
				Description:   "Filter by MAC address (substring match, case-insensitive)",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     2,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:          "interface",
				CLIName:       "interface",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:  "",
				Description:   "Filter by interface name (case-insensitive exact match)",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     3,
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
			return agentstructs.PTTTaskOPSECPreTaskMessageResponse{
				TaskID: taskData.Task.ID, Success: true,
				OpsecPreBlocked: false,
				OpsecPreMessage:    "OPSEC WARNING: Reading ARP table for IP-to-MAC address mappings (T1016.001). Low risk — reads cached network data. No network traffic generated.",
				OpsecPreBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionProcessResponse: func(processResponse agentstructs.PtTaskProcessResponseMessage) agentstructs.PTTaskProcessResponseMessageResponse {
			response := agentstructs.PTTaskProcessResponseMessageResponse{
				TaskID:  processResponse.TaskData.Task.ID,
				Success: true,
			}
			responseText, ok := processResponse.Response.(string)
			if !ok || responseText == "" || responseText == "[]" {
				return response
			}
			type arpEntry struct {
				IP        string `json:"ip"`
				MAC       string `json:"mac"`
				Type      string `json:"type"`
				Interface string `json:"interface"`
			}
			var entries []arpEntry
			if err := json.Unmarshal([]byte(responseText), &entries); err != nil {
				return response
			}
			for _, e := range entries {
				createArtifact(processResponse.TaskData.Task.ID, "Host Discovery",
					fmt.Sprintf("ARP: %s → %s (%s) on %s", e.IP, e.MAC, e.Type, e.Interface))
			}
			return response
		},
		TaskFunctionCreateTasking: func(task *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  task.Task.ID,
			}
			ip, _ := task.Args.GetStringArg("ip")
			mac, _ := task.Args.GetStringArg("mac")
			iface, _ := task.Args.GetStringArg("interface")

			display := "ARP table"
			if ip != "" {
				display += fmt.Sprintf(", ip=%s", ip)
			}
			if mac != "" {
				display += fmt.Sprintf(", mac=%s", mac)
			}
			if iface != "" {
				display += fmt.Sprintf(", interface=%s", iface)
			}
			response.DisplayParams = &display

			if task.Callback.OS == "macOS" {
				createArtifact(task.Task.ID, "Process Create", "arp -a")
			} else {
				createArtifact(task.Task.ID, "API Call", "GetIpNetTable / /proc/net/arp")
			}
			return response
		},
	})
}
