package agentfunctions

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
	"github.com/MythicMeta/MythicContainer/mythicrpc"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name: "dns",
		AssociatedBrowserScript: &agentstructs.BrowserScript{
			ScriptPath: filepath.Join(".", "fawkes", "browserscripts", "dns_new.js"),
			Author:     "@galoryber",
		},
		Description:         "DNS enumeration — resolve hosts, query record types (A, MX, NS, SRV, TXT, CNAME), reverse lookups, and discover domain controllers via SRV records.",
		HelpString:          "dns -action resolve -target example.com\ndns -action dc -target corp.local\ndns -action srv -target _ldap._tcp.corp.local\ndns -action all -target corp.local",
		Version:             1,
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1018"},
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{
				agentstructs.SUPPORTED_OS_WINDOWS,
				agentstructs.SUPPORTED_OS_LINUX,
				agentstructs.SUPPORTED_OS_MACOS,
			},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:             "action",
				CLIName:          "action",
				ModalDisplayName: "Action",
				Description:      "DNS query type: resolve (A/AAAA), reverse (PTR), srv, mx, ns, txt, cname, all, dc (domain controller discovery), zone-transfer (AXFR), wildcard (detect wildcard DNS)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:          []string{"resolve", "reverse", "srv", "mx", "ns", "txt", "cname", "all", "dc", "zone-transfer", "wildcard"},
				DefaultValue:     "resolve",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: true, GroupName: "Default"},
				},
			},
			{
				Name:             "target",
				CLIName:          "target",
				ModalDisplayName: "Target",
				Description:      "Hostname, IP address, or domain to query",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: true, GroupName: "Default"},
				},
			},
			{
				Name:             "server",
				CLIName:          "server",
				ModalDisplayName: "DNS Server",
				Description:      "Custom DNS server to query (default: system resolver)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "timeout",
				CLIName:          "timeout",
				ModalDisplayName: "Timeout (seconds)",
				Description:      "Query timeout in seconds (default: 5)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				DefaultValue:     5,
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
			msg := fmt.Sprintf("OPSEC WARNING: DNS queries from agent (action: %s). Bulk DNS enumeration may trigger DNS monitoring alerts. Zone transfers and SRV queries for domain controllers are suspicious patterns (T1018, T1046).", action)
			return agentstructs.PTTTaskOPSECPreTaskMessageResponse{
				TaskID: taskData.Task.ID, Success: true,
				OpsecPreBlocked: false, OpsecPreMessage: msg,
				OpsecPreBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionOPSECPost: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskOPSECPostTaskMessageResponse {
			return agentstructs.PTTaskOPSECPostTaskMessageResponse{
				TaskID:              taskData.Task.ID,
				Success:             true,
				OpsecPostBlocked:    false,
				OpsecPostMessage:    "OPSEC AUDIT: DNS operations completed. DNS queries are logged in DNS server logs and may be captured by DNS monitoring tools. Zone transfer (AXFR) attempts are particularly noisy and often alerting. Passive DNS collectors may record query patterns.",
				OpsecPostBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
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
			// DC discovery: "host:port → IP"
			dcRe := regexp.MustCompile(`(\S+):(\d+)\s*→\s*(\S+)`)
			// Standalone IPv4 address lines (resolve action output)
			ipRe := regexp.MustCompile(`^\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s*$`)

			seen := make(map[string]bool)
			for _, line := range strings.Split(responseText, "\n") {
				if m := dcRe.FindStringSubmatch(line); m != nil {
					host, port, ip := m[1], m[2], m[3]
					key := host + ":" + port
					if !seen[key] {
						seen[key] = true
						createArtifact(processResponse.TaskData.Task.ID, "Host Discovery",
							fmt.Sprintf("DNS DC: %s:%s (%s)", host, port, ip))
					}
					continue
				}
				if m := ipRe.FindStringSubmatch(line); m != nil {
					ip := m[1]
					if !seen[ip] {
						seen[ip] = true
						createArtifact(processResponse.TaskData.Task.ID, "Host Discovery",
							fmt.Sprintf("DNS resolved: %s", ip))
					}
				}
			}
			return response
		},
		TaskFunctionCreateTasking: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  taskData.Task.ID,
			}

			action, _ := taskData.Args.GetStringArg("action")
			target, _ := taskData.Args.GetStringArg("target")

			displayMsg := fmt.Sprintf("DNS %s %s", action, target)
			response.DisplayParams = &displayMsg

			mythicrpc.SendMythicRPCArtifactCreate(mythicrpc.MythicRPCArtifactCreateMessage{
				TaskID:           taskData.Task.ID,
				BaseArtifactType: "API Call",
				ArtifactMessage:  fmt.Sprintf("DNS %s query for %s", action, target),
			})

			return response
		},
	})
}
