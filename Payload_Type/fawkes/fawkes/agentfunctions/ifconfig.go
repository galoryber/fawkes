package agentfunctions

import (
	"fmt"
	"strings"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
	"github.com/MythicMeta/MythicContainer/logging"
	"github.com/MythicMeta/MythicContainer/mythicrpc"
)

// Chain completion functions for ifconfig recon-chain
func ifconfigReconArpDone(taskData *agentstructs.PTTaskMessageAllData, subtaskData *agentstructs.PTTaskMessageAllData, _ *agentstructs.SubtaskGroupName) agentstructs.PTTaskCompletionFunctionMessageResponse {
	response := agentstructs.PTTaskCompletionFunctionMessageResponse{TaskID: taskData.Task.ID, Success: true}
	mythicrpc.SendMythicRPCResponseCreate(mythicrpc.MythicRPCResponseCreateMessage{
		TaskID: taskData.Task.ID, Response: []byte("[2/4] ARP table collected. Running DNS reverse lookups..."),
	})
	// Get IPs from chain context stored in parent stdout
	ctx := extractChainContext(taskData.Task.Stdout)
	subnets := ctx["subnets"]
	if subnets == "" {
		subnets = "192.168.0.0/24"
	}
	cb := "ifconfigReconDnsDone"
	if _, err := mythicrpc.SendMythicRPCTaskCreateSubtask(mythicrpc.MythicRPCTaskCreateSubtaskMessage{
		TaskID: taskData.Task.ID, SubtaskCallbackFunction: &cb,
		CommandName: "dns", Params: fmt.Sprintf(`{"action":"reverse","target":"%s"}`, subnets),
	}); err != nil {
		response.Success = false
		response.Error = fmt.Sprintf("Failed to create dns subtask: %v", err)
	}
	return response
}

func ifconfigReconDnsDone(taskData *agentstructs.PTTaskMessageAllData, subtaskData *agentstructs.PTTaskMessageAllData, _ *agentstructs.SubtaskGroupName) agentstructs.PTTaskCompletionFunctionMessageResponse {
	response := agentstructs.PTTaskCompletionFunctionMessageResponse{TaskID: taskData.Task.ID, Success: true}
	mythicrpc.SendMythicRPCResponseCreate(mythicrpc.MythicRPCResponseCreateMessage{
		TaskID: taskData.Task.ID, Response: []byte("[3/4] DNS reverse lookups complete. Running port scan..."),
	})
	ctx := extractChainContext(taskData.Task.Stdout)
	subnets := ctx["subnets"]
	if subnets == "" {
		subnets = "192.168.0.0/24"
	}
	cb := "ifconfigReconPortscanDone"
	if _, err := mythicrpc.SendMythicRPCTaskCreateSubtask(mythicrpc.MythicRPCTaskCreateSubtaskMessage{
		TaskID: taskData.Task.ID, SubtaskCallbackFunction: &cb,
		CommandName: "port-scan", Params: fmt.Sprintf(`{"hosts":"%s","ports":"21,22,23,25,53,80,88,135,139,389,443,445,636,1433,3306,3389,5432,5985,8080,8443"}`, subnets),
	}); err != nil {
		response.Success = false
		response.Error = fmt.Sprintf("Failed to create port-scan subtask: %v", err)
	}
	return response
}

func ifconfigReconPortscanDone(taskData *agentstructs.PTTaskMessageAllData, subtaskData *agentstructs.PTTaskMessageAllData, _ *agentstructs.SubtaskGroupName) agentstructs.PTTaskCompletionFunctionMessageResponse {
	response := agentstructs.PTTaskCompletionFunctionMessageResponse{TaskID: taskData.Task.ID, Success: true}
	parentID := taskData.Task.ID
	searchResult, _ := mythicrpc.SendMythicRPCTaskSearch(mythicrpc.MythicRPCTaskSearchMessage{
		TaskID: parentID, SearchParentTaskID: &parentID,
	})
	summary := "=== Network Recon Chain Complete ===\n"
	successCount := 0
	errorCount := 0
	if searchResult != nil && searchResult.Success {
		for _, task := range searchResult.Tasks {
			status := "OK"
			if task.Status == "error" {
				status = "FAIL"
				errorCount++
			} else {
				successCount++
			}
			summary += fmt.Sprintf("  [%s] %s\n", status, task.CommandName)
		}
	}
	summary += fmt.Sprintf("\nSteps: %d/%d successful\n", successCount, successCount+errorCount)
	completed := true
	response.Completed = &completed
	response.Stdout = &summary
	mythicrpc.SendMythicRPCResponseCreate(mythicrpc.MythicRPCResponseCreateMessage{
		TaskID: taskData.Task.ID, Response: []byte(summary),
	})
	logOperationEvent(taskData.Task.ID, fmt.Sprintf("[RECON] Network recon chain on %s: %d/%d steps successful", taskData.Callback.Host, successCount, successCount+errorCount), false)
	return response
}

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "ifconfig",
		Description:         "List network interfaces and their addresses",
		HelpString:          "ifconfig",
		Version:             1,
		SupportedUIFeatures: []string{},
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1016"},
		ScriptOnlyCommand: false,
		TaskCompletionFunctions: map[string]agentstructs.PTTaskCompletionFunction{
			"ifconfigReconArpDone":      ifconfigReconArpDone,
			"ifconfigReconDnsDone":      ifconfigReconDnsDone,
			"ifconfigReconPortscanDone": ifconfigReconPortscanDone,
		},
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_LINUX, agentstructs.SUPPORTED_OS_MACOS, agentstructs.SUPPORTED_OS_WINDOWS},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:          "action",
				CLIName:       "action",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:       []string{"info", "recon-chain"},
				DefaultValue:  "info",
				Description:   "info: list interfaces. recon-chain: ifconfig → arp → dns reverse → port-scan.",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
		},
		AssociatedBrowserScript: nil,
		TaskFunctionOPSECPre: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTTaskOPSECPreTaskMessageResponse {
				return agentstructs.PTTTaskOPSECPreTaskMessageResponse{
					TaskID:             taskData.Task.ID,
					Success:            true,
					OpsecPreBlocked:    false,
					OpsecPreMessage:    "OPSEC WARNING: Network interface enumeration reveals IP addresses, MAC addresses, and network topology. Updates Mythic callback IP metadata.",
					OpsecPreBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
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
			// Extract non-loopback IPv4 addresses from "inet <ip>/<cidr>" lines
			var ips []string
			for _, line := range strings.Split(responseText, "\n") {
				trimmed := strings.TrimSpace(line)
				if strings.HasPrefix(trimmed, "inet ") && !strings.HasPrefix(trimmed, "inet6 ") {
					parts := strings.Fields(trimmed)
					if len(parts) >= 2 {
						ipCidr := parts[1]
						ip := strings.SplitN(ipCidr, "/", 2)[0]
						if ip != "127.0.0.1" && ip != "" {
							ips = append(ips, ip)
						}
					}
				}
			}
			if len(ips) > 0 {
				update := mythicrpc.MythicRPCCallbackUpdateMessage{
					AgentCallbackID: &processResponse.TaskData.Callback.AgentCallbackID,
					IPs:               &ips,
				}
				if len(ips) == 1 {
					update.Ip = &ips[0]
				}
				if _, err := mythicrpc.SendMythicRPCCallbackUpdate(update); err != nil {
					logging.LogError(err, "Failed to update callback IPs from ifconfig")
				}
			}
			return response
		},
		TaskFunctionOPSECPost: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskOPSECPostTaskMessageResponse {
			return agentstructs.PTTaskOPSECPostTaskMessageResponse{
				TaskID:              taskData.Task.ID,
				Success:             true,
				OpsecPostBlocked:    false,
				OpsecPostMessage:    "OPSEC AUDIT: Network interface enumeration completed. Interface details (IPs, MACs, MTU) reveal network topology and multi-homed hosts. This is standard reconnaissance but results may inform pivot planning. No persistent artifacts created.",
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
			action, _ := taskData.Args.GetStringArg("action")
			if action == "recon-chain" {
				display := "recon-chain: ifconfig → arp → dns → port-scan"
				response.DisplayParams = &display
				// Derive /24 subnet from callback IP for scanning
				subnets := "192.168.0.0/24"
				if taskData.Callback.IP != "" {
					parts := strings.SplitN(taskData.Callback.IP, ".", 4)
					if len(parts) == 4 {
						subnets = parts[0] + "." + parts[1] + "." + parts[2] + ".0/24"
					}
				}
				// Store context for chain steps
				ctxStr := fmt.Sprintf(`{"subnets":"%s"}`, subnets)
				response.Stdout = &ctxStr
				// Agent runs normal ifconfig (step 1). Then chain continues via ARP.
				cb := "ifconfigReconArpDone"
				if _, err := mythicrpc.SendMythicRPCTaskCreateSubtask(mythicrpc.MythicRPCTaskCreateSubtaskMessage{
					TaskID: taskData.Task.ID, SubtaskCallbackFunction: &cb, CommandName: "arp", Params: `{}`,
				}); err != nil {
					response.Success = false
					response.Error = fmt.Sprintf("Failed to start recon chain: %v", err)
					return response
				}
				createArtifact(taskData.Task.ID, "Subtask Chain", fmt.Sprintf("Network Recon: ifconfig → arp → dns reverse → port-scan (%s)", subnets))
				return response
			}
			display := "Network interfaces"
			response.DisplayParams = &display
			return response
		},
	})
}
