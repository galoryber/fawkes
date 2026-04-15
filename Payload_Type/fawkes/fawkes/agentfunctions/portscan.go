package agentfunctions

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
	"github.com/MythicMeta/MythicContainer/mythicrpc"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "port-scan",
		Description:         "TCP connect scan for network service discovery",
		HelpString:          "port-scan -hosts <IPs/CIDRs> [-ports <ports>] [-timeout <seconds>] [-concurrency <num>]",
		Version:             1,
		SupportedUIFeatures: []string{},
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1046"},
		ScriptOnlyCommand:   false,
		AssociatedBrowserScript: &agentstructs.BrowserScript{
			ScriptPath: filepath.Join(".", "fawkes", "browserscripts", "portscan_new.js"),
			Author:     "@galoryber",
		},
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_LINUX, agentstructs.SUPPORTED_OS_MACOS, agentstructs.SUPPORTED_OS_WINDOWS},
		},
		TaskCompletionFunctions: map[string]agentstructs.PTTaskCompletionFunction{
			"portReconDnsDone":     portReconDnsDone,
			"portReconArpDone":     portReconArpDone,
			"portReconNetstatDone": portReconNetstatDone,
			"portReconFinalDone":   portReconFinalDone,
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:             "action",
				ModalDisplayName: "Action",
				CLIName:          "action",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:          []string{"scan", "recon-chain"},
				Description:      "scan: standard port scan. recon-chain: automated network recon — portscan → dns reverse → arp → net-stat",
				DefaultValue:     "scan",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:                 "hosts",
				ModalDisplayName:     "Target Hosts",
				CLIName:              "hosts",
				ParameterType:        agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:          "Comma-separated IPs, CIDR ranges, or hostname-ranges (e.g. 192.168.1.1,192.168.1.0/24,10.0.0.1-10)",
				DefaultValue:         "",
				DynamicQueryFunction: getActiveHostList,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: true,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "ports",
				ModalDisplayName: "Ports",
				CLIName:          "ports",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Comma-separated ports or ranges (e.g. 80,443,8080 or 1-1024). Default: common ports",
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "timeout",
				ModalDisplayName: "Timeout (seconds)",
				CLIName:          "timeout",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				Description:      "Connection timeout per port in seconds (default: 2)",
				DefaultValue:     2,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "concurrency",
				ModalDisplayName: "Max Concurrent Connections",
				CLIName:          "concurrency",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				Description:      "Maximum concurrent TCP connections (default: 100)",
				DefaultValue:     100,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
		},
		TaskFunctionOPSECPre: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTTaskOPSECPreTaskMessageResponse {
				hosts, _ := taskData.Args.GetStringArg("hosts")
				ports, _ := taskData.Args.GetStringArg("ports")
				action, _ := taskData.Args.GetStringArg("action")
				msg := fmt.Sprintf("OPSEC WARNING: Port scanning %s (ports: %s). TCP connect scans generate SYN packets to each host:port combination. NDR/IDS systems detect port scan patterns. Host firewalls log blocked connection attempts.", hosts, ports)
				if action == "recon-chain" {
					msg = fmt.Sprintf("OPSEC WARNING: Network Recon Chain against %s. This executes 4 automated steps: (1) port scan, (2) DNS reverse lookups, (3) ARP table enumeration, (4) active connection listing. Combined footprint generates significant network traffic — port scans trigger IDS/IPS, DNS queries are logged, and the multi-step pattern is a behavioral indicator of automated reconnaissance.", hosts)
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
				OpsecPostMessage:    "OPSEC AUDIT: Port scan completed. Scan traffic is visible to network monitoring (IDS/IPS). Connection attempts generate TCP SYN packets that may trigger firewall alerts. Scan timing and source IP are logged in target host firewalls.",
				OpsecPostBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
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
		TaskFunctionCreateTasking: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  taskData.Task.ID,
			}
			hosts, _ := taskData.Args.GetStringArg("hosts")
			ports, _ := taskData.Args.GetStringArg("ports")
			if ports == "" {
				ports = "common"
			}
			action, _ := taskData.Args.GetStringArg("action")

			if action == "recon-chain" {
				if hosts == "" {
					response.Success = false
					response.Error = "recon-chain requires -hosts parameter (e.g., 192.168.1.0/24)"
					return response
				}

				display := fmt.Sprintf("Recon Chain: %s (ports: %s) → dns reverse → arp → net-stat", hosts, ports)
				response.DisplayParams = &display

				// Store hosts for completion functions
				chainCtx, _ := json.Marshal(map[string]string{
					"hosts": hosts,
					"ports": ports,
				})
				chainCtxStr := string(chainCtx)
				response.Stdout = &chainCtxStr

				// Step 1: Run port scan as subtask
				callbackFunc := "portReconDnsDone"
				_, err := mythicrpc.SendMythicRPCTaskCreateSubtask(
					mythicrpc.MythicRPCTaskCreateSubtaskMessage{
						TaskID:                  taskData.Task.ID,
						SubtaskCallbackFunction: &callbackFunc,
						CommandName:             "port-scan",
						Params:                  fmt.Sprintf(`{"action":"scan","hosts":"%s","ports":"%s"}`, hosts, ports),
					},
				)
				if err != nil {
					response.Success = false
					response.Error = fmt.Sprintf("Failed to create portscan subtask: %s", err.Error())
					return response
				}

				createArtifact(taskData.Task.ID, "Subtask Chain",
					fmt.Sprintf("Network Recon Chain: portscan %s → dns reverse → arp → net-stat", hosts))
				logOperationEvent(taskData.Task.ID,
					fmt.Sprintf("[CHAIN] Network recon started against %s", hosts), false)
				return response
			}

			display := fmt.Sprintf("%s ports:%s", hosts, ports)
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
			// Parse: "192.168.1.1          22       SSH" (column-aligned text table)
			re := regexp.MustCompile(`^(\d+\.\d+\.\d+\.\d+)\s+(\d+)\s+(\S+)`)
			type portResult struct {
				Host    string `json:"host"`
				Port    string `json:"port"`
				Service string `json:"service"`
			}
			var results []portResult
			for _, line := range strings.Split(responseText, "\n") {
				m := re.FindStringSubmatch(strings.TrimSpace(line))
				if m == nil {
					continue
				}
				createArtifact(processResponse.TaskData.Task.ID, "Host Discovery",
					fmt.Sprintf("Port scan: %s:%s (%s)", m[1], m[2], m[3]))
				results = append(results, portResult{Host: m[1], Port: m[2], Service: m[3]})
			}
			// Cache port scan results in AgentStorage for network topology mapping
			if len(results) > 0 {
				callbackID := fmt.Sprintf("%d", processResponse.TaskData.Callback.DisplayID)
				storageKey := "portscan-cb" + callbackID
				if storageData, err := json.Marshal(results); err == nil {
					storeAgentData(storageKey, storageData)
				}
			}
			return response
		},
	})
}

// portReconDnsDone handles portscan completion, performs DNS reverse lookups on discovered hosts.
func portReconDnsDone(taskData *agentstructs.PTTaskMessageAllData, subtaskData *agentstructs.PTTaskMessageAllData, groupName *agentstructs.SubtaskGroupName) agentstructs.PTTaskCompletionFunctionMessageResponse {
	response := agentstructs.PTTaskCompletionFunctionMessageResponse{
		TaskID:  taskData.Task.ID,
		Success: true,
	}

	responseText := getSubtaskResponses(subtaskData.Task.ID)
	if responseText == "" {
		completed := true
		response.Completed = &completed
		msg := "Recon Chain: portscan returned no results — no hosts responded"
		response.Stdout = &msg
		mythicrpc.SendMythicRPCResponseCreate(mythicrpc.MythicRPCResponseCreateMessage{
			TaskID: taskData.Task.ID, Response: []byte(msg),
		})
		return response
	}

	// Extract unique hosts from portscan output
	hosts := parsePortScanHosts(responseText)
	openPorts := strings.Count(responseText, "\n") - 3 // subtract header lines

	mythicrpc.SendMythicRPCResponseCreate(mythicrpc.MythicRPCResponseCreateMessage{
		TaskID:   taskData.Task.ID,
		Response: []byte(fmt.Sprintf("[Step 1/4] Portscan complete. %d open ports across %d hosts.", openPorts, len(hosts))),
	})

	if len(hosts) == 0 {
		completed := true
		response.Completed = &completed
		msg := "Recon Chain complete: no responsive hosts found"
		response.Stdout = &msg
		mythicrpc.SendMythicRPCResponseCreate(mythicrpc.MythicRPCResponseCreateMessage{
			TaskID: taskData.Task.ID, Response: []byte(msg),
		})
		return response
	}

	// Step 2: DNS reverse lookup on all discovered hosts
	hostsStr := strings.Join(hosts, ",")
	callbackFunc := "portReconArpDone"
	_, err := mythicrpc.SendMythicRPCTaskCreateSubtask(
		mythicrpc.MythicRPCTaskCreateSubtaskMessage{
			TaskID:                  taskData.Task.ID,
			SubtaskCallbackFunction: &callbackFunc,
			CommandName:             "dns",
			Params:                  fmt.Sprintf(`{"action":"reverse","target":"%s"}`, hostsStr),
		},
	)
	if err != nil {
		completed := true
		response.Completed = &completed
		msg := fmt.Sprintf("Recon Chain: portscan done but failed to start dns reverse: %s", err.Error())
		response.Stderr = &msg
		return response
	}

	return response
}

// portReconArpDone handles DNS reverse completion, runs ARP table scan.
func portReconArpDone(taskData *agentstructs.PTTaskMessageAllData, subtaskData *agentstructs.PTTaskMessageAllData, groupName *agentstructs.SubtaskGroupName) agentstructs.PTTaskCompletionFunctionMessageResponse {
	response := agentstructs.PTTaskCompletionFunctionMessageResponse{
		TaskID:  taskData.Task.ID,
		Success: true,
	}

	responseText := getSubtaskResponses(subtaskData.Task.ID)
	resolvedCount := 0
	if responseText != "" {
		for _, line := range strings.Split(responseText, "\n") {
			if strings.Contains(line, "→") || strings.Contains(line, "->") {
				resolvedCount++
			}
		}
	}

	mythicrpc.SendMythicRPCResponseCreate(mythicrpc.MythicRPCResponseCreateMessage{
		TaskID:   taskData.Task.ID,
		Response: []byte(fmt.Sprintf("[Step 2/4] DNS reverse complete. %d hostnames resolved.", resolvedCount)),
	})

	// Step 3: ARP table — shows MAC addresses and local neighbors
	callbackFunc := "portReconNetstatDone"
	_, err := mythicrpc.SendMythicRPCTaskCreateSubtask(
		mythicrpc.MythicRPCTaskCreateSubtaskMessage{
			TaskID:                  taskData.Task.ID,
			SubtaskCallbackFunction: &callbackFunc,
			CommandName:             "arp",
			Params:                  "{}",
		},
	)
	if err != nil {
		completed := true
		response.Completed = &completed
		msg := fmt.Sprintf("Recon Chain: dns done but failed to start arp: %s", err.Error())
		response.Stderr = &msg
		return response
	}

	return response
}

// portReconNetstatDone handles ARP completion, runs net-stat for active connections.
func portReconNetstatDone(taskData *agentstructs.PTTaskMessageAllData, subtaskData *agentstructs.PTTaskMessageAllData, groupName *agentstructs.SubtaskGroupName) agentstructs.PTTaskCompletionFunctionMessageResponse {
	response := agentstructs.PTTaskCompletionFunctionMessageResponse{
		TaskID:  taskData.Task.ID,
		Success: true,
	}

	responseText := getSubtaskResponses(subtaskData.Task.ID)
	arpEntries := 0
	if responseText != "" {
		for _, line := range strings.Split(responseText, "\n") {
			line = strings.TrimSpace(line)
			if line != "" && !strings.HasPrefix(line, "IP") && !strings.HasPrefix(line, "-") {
				arpEntries++
			}
		}
	}

	mythicrpc.SendMythicRPCResponseCreate(mythicrpc.MythicRPCResponseCreateMessage{
		TaskID:   taskData.Task.ID,
		Response: []byte(fmt.Sprintf("[Step 3/4] ARP table complete. %d neighbor entries.", arpEntries)),
	})

	// Step 4 (final): net-stat for active connections — shows established connections
	// We use a simple completion aggregator since this is the last step
	callbackFunc := "portReconFinalDone"

	// Register the final completion function dynamically isn't possible,
	// so we aggregate here by creating the subtask without a callback
	// and completing the parent task once the subtask completes
	_, err := mythicrpc.SendMythicRPCTaskCreateSubtask(
		mythicrpc.MythicRPCTaskCreateSubtaskMessage{
			TaskID:                  taskData.Task.ID,
			SubtaskCallbackFunction: &callbackFunc,
			CommandName:             "net-stat",
			Params:                  `{"state":"ESTABLISHED"}`,
		},
	)
	if err != nil {
		// If net-stat fails to create, still complete the chain
		completed := true
		response.Completed = &completed
		summary := portReconAggregate(taskData.Task.ID)
		response.Stdout = &summary
		mythicrpc.SendMythicRPCResponseCreate(mythicrpc.MythicRPCResponseCreateMessage{
			TaskID: taskData.Task.ID, Response: []byte(summary),
		})
		return response
	}

	return response
}

// portReconFinalDone handles net-stat completion, aggregates all chain results.
func portReconFinalDone(taskData *agentstructs.PTTaskMessageAllData, subtaskData *agentstructs.PTTaskMessageAllData, groupName *agentstructs.SubtaskGroupName) agentstructs.PTTaskCompletionFunctionMessageResponse {
	response := agentstructs.PTTaskCompletionFunctionMessageResponse{
		TaskID:  taskData.Task.ID,
		Success: true,
	}

	responseText := getSubtaskResponses(subtaskData.Task.ID)
	connCount := 0
	if responseText != "" {
		for _, line := range strings.Split(responseText, "\n") {
			line = strings.TrimSpace(line)
			if line != "" && !strings.HasPrefix(line, "Proto") && !strings.HasPrefix(line, "-") {
				connCount++
			}
		}
	}

	mythicrpc.SendMythicRPCResponseCreate(mythicrpc.MythicRPCResponseCreateMessage{
		TaskID:   taskData.Task.ID,
		Response: []byte(fmt.Sprintf("[Step 4/4] Net-stat complete. %d active connections.", connCount)),
	})

	summary := portReconAggregate(taskData.Task.ID)
	completed := true
	response.Completed = &completed
	response.Stdout = &summary

	mythicrpc.SendMythicRPCResponseCreate(mythicrpc.MythicRPCResponseCreateMessage{
		TaskID: taskData.Task.ID, Response: []byte(summary),
	})

	return response
}

// parsePortScanHosts extracts unique host IPs from portscan text output.
func parsePortScanHosts(responseText string) []string {
	hostSet := map[string]bool{}
	re := regexp.MustCompile(`^(\d+\.\d+\.\d+\.\d+)\s+`)
	for _, line := range strings.Split(responseText, "\n") {
		m := re.FindStringSubmatch(strings.TrimSpace(line))
		if m != nil {
			hostSet[m[1]] = true
		}
	}
	var hosts []string
	for h := range hostSet {
		hosts = append(hosts, h)
	}
	return hosts
}

// portReconAggregate collects all subtask results into a summary.
func portReconAggregate(parentTaskID int) string {
	searchResult, err := mythicrpc.SendMythicRPCTaskSearch(mythicrpc.MythicRPCTaskSearchMessage{
		TaskID:             parentTaskID,
		SearchParentTaskID: &parentTaskID,
	})

	summary := "=== Network Recon Chain Complete ===\n"
	if err == nil && searchResult.Success {
		successCount := 0
		errorCount := 0
		for _, task := range searchResult.Tasks {
			status := task.Status
			if task.Status == "error" {
				errorCount++
			} else if task.Completed {
				successCount++
			}
			summary += fmt.Sprintf("[%s] %s %s\n", status, task.CommandName, task.DisplayParams)
		}
		summary += fmt.Sprintf("\nTotal: %d subtasks (%d success, %d errors)\n", len(searchResult.Tasks), successCount, errorCount)
	} else {
		summary += "Could not retrieve subtask details.\n"
	}
	return summary
}
