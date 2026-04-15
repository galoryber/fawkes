package agentfunctions

import (
	"encoding/json"
	"fmt"
	"path/filepath"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "route",
		Description:         "Display the system routing table with optional filtering. Windows: GetIpForwardTable API. Linux: /proc/net/route. macOS: netstat -rn.",
		HelpString:          "route [-destination <IP>] [-gateway <IP>] [-interface <name>]",
		Version:             2,
		MitreAttackMappings: []string{"T1016"},
		Author:              "@galoryber",
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_LINUX, agentstructs.SUPPORTED_OS_MACOS, agentstructs.SUPPORTED_OS_WINDOWS},
		},
		AssociatedBrowserScript: &agentstructs.BrowserScript{
			ScriptPath: filepath.Join(".", "fawkes", "browserscripts", "route_new.js"),
			Author:     "@galoryber",
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:          "destination",
				CLIName:       "destination",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:  "",
				Description:   "Filter by destination IP or subnet (substring match)",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     1,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:          "gateway",
				CLIName:       "gateway",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:  "",
				Description:   "Filter by gateway IP (substring match)",
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
				Description:   "Filter by network interface name (case-insensitive)",
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
				OpsecPreMessage:    "OPSEC WARNING: Reading routing table (T1016). Low risk — reads cached kernel data. No network traffic generated.",
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
			type routeEntry struct {
				Destination string `json:"destination"`
				Gateway     string `json:"gateway"`
				Netmask     string `json:"netmask"`
				Interface   string `json:"interface"`
				Metric      uint32 `json:"metric"`
				Flags       string `json:"flags"`
			}
			var routes []routeEntry
			if err := json.Unmarshal([]byte(responseText), &routes); err != nil {
				return response
			}
			for _, r := range routes {
				if r.Gateway == "0.0.0.0" || r.Gateway == "::" || r.Gateway == "*" || r.Gateway == "" {
					continue
				}
				createArtifact(processResponse.TaskData.Task.ID, "Network Route",
					fmt.Sprintf("%s/%s via %s on %s (metric %d)", r.Destination, r.Netmask, r.Gateway, r.Interface, r.Metric))
			}
			return response
		},
		TaskFunctionOPSECPost: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskOPSECPostTaskMessageResponse {
			return agentstructs.PTTaskOPSECPostTaskMessageResponse{
				TaskID:              taskData.Task.ID,
				Success:             true,
				OpsecPostBlocked:    false,
				OpsecPostMessage:    "OPSEC AUDIT: Routing table enumeration completed. Routes reveal network segments, gateways, and VPN tunnels. GetIpForwardTable API call is low-noise but results inform network pivoting and lateral movement planning.",
				OpsecPostBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionCreateTasking: func(task *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  task.Task.ID,
			}
			dest, _ := task.Args.GetStringArg("destination")
			gw, _ := task.Args.GetStringArg("gateway")
			iface, _ := task.Args.GetStringArg("interface")
			display := "Routing table"
			if dest != "" {
				display += fmt.Sprintf(", destination=%s", dest)
			}
			if gw != "" {
				display += fmt.Sprintf(", gateway=%s", gw)
			}
			if iface != "" {
				display += fmt.Sprintf(", interface=%s", iface)
			}
			response.DisplayParams = &display
			return response
		},
	})
}
