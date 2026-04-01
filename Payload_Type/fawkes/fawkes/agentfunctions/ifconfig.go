package agentfunctions

import (
	"fmt"
	"strings"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
	"github.com/MythicMeta/MythicContainer/logging"
	"github.com/MythicMeta/MythicContainer/mythicrpc"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "ifconfig",
		Description:         "List network interfaces and their addresses",
		HelpString:          "ifconfig",
		Version:             1,
		SupportedUIFeatures: []string{},
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1016"},
		ScriptOnlyCommand:   false,
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_LINUX, agentstructs.SUPPORTED_OS_MACOS, agentstructs.SUPPORTED_OS_WINDOWS},
		},
		CommandParameters:       []agentstructs.CommandParameter{},
		AssociatedBrowserScript: nil,
		TaskFunctionOPSECPre:    nil,
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
		TaskFunctionCreateTasking: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  taskData.Task.ID,
			}
			display := fmt.Sprintf("Network interfaces")
			response.DisplayParams = &display
			return response
		},
	})
}
