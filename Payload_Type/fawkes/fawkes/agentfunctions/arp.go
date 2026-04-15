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
		Description:         "Display ARP table or perform ARP cache poisoning. Default: list IP-to-MAC mappings. spoof: bidirectional ARP poisoning for MITM positioning (T1557.002).",
		HelpString:          "arp [-ip <subnet>] [-mac <prefix>]\narp -action spoof -target <victim_IP> -gateway <gateway_IP> [-duration 120] [-interval 2]",
		Version:             3,
		MitreAttackMappings: []string{"T1016.001", "T1557.002"},
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
				Name:          "action",
				CLIName:       "action",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:       []string{"", "spoof"},
				DefaultValue:  "",
				Description:   "Action: empty (list ARP table, default) or spoof (ARP cache poisoning for MITM)",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
					{ParameterIsRequired: true, GroupName: "Spoof"},
				},
			},
			{
				Name:          "target",
				CLIName:       "target",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:  "",
				Description:   "Victim IP to poison (spoof mode). Traffic between target and gateway will route through attacker.",
				DynamicQueryFunction: getActiveHostList,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: true, GroupName: "Spoof"},
				},
			},
			{
				Name:          "gateway",
				CLIName:       "gateway",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:  "",
				Description:   "Gateway IP to impersonate (spoof mode). Usually the default gateway.",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: true, GroupName: "Spoof"},
				},
			},
			{
				Name:          "duration",
				CLIName:       "duration",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				DefaultValue:  120,
				Description:   "Spoofing duration in seconds (default: 120, max: 600)",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Spoof"},
				},
			},
			{
				Name:          "interval",
				CLIName:       "interval",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				DefaultValue:  2,
				Description:   "Seconds between ARP reply packets (default: 2)",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Spoof"},
				},
			},
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
			action, _ := taskData.Args.GetStringArg("action")
			var msg string
			if action == "spoof" {
				target, _ := taskData.Args.GetStringArg("target")
				gateway, _ := taskData.Args.GetStringArg("gateway")
				msg = fmt.Sprintf("OPSEC CRITICAL: ARP cache poisoning (T1557.002) between %s and %s. "+
					"Bidirectional gratuitous ARP replies will be sent to position as MITM. "+
					"This generates anomalous ARP traffic that IDS/IPS signatures specifically detect. "+
					"ARP storms, duplicate IP warnings, and port security violations may be triggered. "+
					"IP forwarding will be enabled on the host. Requires root/admin for raw sockets.", target, gateway)
			} else {
				msg = "OPSEC WARNING: Reading ARP table for IP-to-MAC address mappings (T1016.001). Low risk — reads cached network data. No network traffic generated."
			}
			return agentstructs.PTTTaskOPSECPreTaskMessageResponse{
				TaskID: taskData.Task.ID, Success: true,
				OpsecPreBlocked: false,
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
			if !ok || responseText == "" || responseText == "[]" {
				return response
			}

			// Check for spoof result
			var spoofResult struct {
				Target      string `json:"target"`
				Gateway     string `json:"gateway"`
				PacketsSent int    `json:"packets_sent"`
				Restored    bool   `json:"arp_restored"`
			}
			if err := json.Unmarshal([]byte(responseText), &spoofResult); err == nil && spoofResult.Target != "" {
				createArtifact(processResponse.TaskData.Task.ID, "MITM Positioning",
					fmt.Sprintf("ARP spoof: %s ↔ attacker ↔ %s (%d packets, restored=%v)",
						spoofResult.Target, spoofResult.Gateway, spoofResult.PacketsSent, spoofResult.Restored))
				return response
			}

			// ARP table listing
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
		TaskFunctionOPSECPost: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskOPSECPostTaskMessageResponse {
			return agentstructs.PTTaskOPSECPostTaskMessageResponse{
				TaskID:              taskData.Task.ID,
				Success:             true,
				OpsecPostBlocked:    false,
				OpsecPostMessage:    "OPSEC AUDIT: ARP table enumeration completed. ARP cache contents reveal local network topology and active hosts. On Windows, GetIpNetTable API call may be logged by EDR. Results may inform follow-up lateral movement — defenders should monitor for subsequent connection attempts to discovered hosts.",
				OpsecPostBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionCreateTasking: func(task *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  task.Task.ID,
			}
			action, _ := task.Args.GetStringArg("action")

			if action == "spoof" {
				target, _ := task.Args.GetStringArg("target")
				gateway, _ := task.Args.GetStringArg("gateway")
				display := fmt.Sprintf("spoof: %s ↔ attacker ↔ %s", target, gateway)
				response.DisplayParams = &display
				createArtifact(task.Task.ID, "Raw Socket", fmt.Sprintf("AF_PACKET ARP spoof: %s ↔ %s", target, gateway))
				return response
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
