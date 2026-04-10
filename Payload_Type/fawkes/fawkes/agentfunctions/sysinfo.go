package agentfunctions

import (
	"strconv"
	"strings"

	"path/filepath"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
	"github.com/MythicMeta/MythicContainer/logging"
	"github.com/MythicMeta/MythicContainer/mythicrpc"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "sysinfo",
		Description:         "sysinfo - Collect comprehensive system information: OS version, hardware, memory, uptime, domain membership, .NET versions (Windows), SELinux/SIP status, virtualization detection.",
		HelpString:          "sysinfo",
		Version:             1,
		MitreAttackMappings: []string{"T1082"}, // System Information Discovery
		Author:              "@galoryber",
		AssociatedBrowserScript: &agentstructs.BrowserScript{ScriptPath: filepath.Join(".", "fawkes", "browserscripts", "sysinfo_new.js"), Author: "@galoryber"},
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_LINUX, agentstructs.SUPPORTED_OS_MACOS, agentstructs.SUPPORTED_OS_WINDOWS},
		},
		CommandParameters: []agentstructs.CommandParameter{},
		TaskFunctionProcessResponse: func(processResponse agentstructs.PtTaskProcessResponseMessage) agentstructs.PTTaskProcessResponseMessageResponse {
			response := agentstructs.PTTaskProcessResponseMessageResponse{
				TaskID:  processResponse.TaskData.Task.ID,
				Success: true,
			}
			responseText, ok := processResponse.Response.(string)
			if !ok || responseText == "" {
				return response
			}
			update := mythicrpc.MythicRPCCallbackUpdateMessage{
				AgentCallbackID: &processResponse.TaskData.Callback.AgentCallbackID,
			}
			hasUpdate := false
			for _, line := range strings.Split(responseText, "\n") {
				trimmed := strings.TrimSpace(line)
				if val := extractField(trimmed, "Hostname:"); val != "" {
					update.Host = &val
					hasUpdate = true
				} else if val := extractField(trimmed, "OS:"); val != "" {
					update.Os = &val
					hasUpdate = true
				} else if val := extractField(trimmed, "Architecture:"); val != "" {
					update.Architecture = &val
					hasUpdate = true
				} else if val := extractField(trimmed, "PID:"); val != "" {
					if pid, err := strconv.Atoi(val); err == nil {
						update.PID = &pid
						hasUpdate = true
					}
				} else if val := extractField(trimmed, "Domain:"); val != "" {
					if !strings.Contains(val, "not domain-joined") {
						update.Domain = &val
						hasUpdate = true
					}
				} else if val := extractField(trimmed, "FQDN:"); val != "" {
					update.Host = &val
					hasUpdate = true
				} else if val := extractField(trimmed, "Elevated:"); val != "" {
					if strings.EqualFold(val, "true") {
						level := 3 // High
						update.IntegrityLevel = &level
						hasUpdate = true
					}
				}
			}
			if hasUpdate {
				if _, err := mythicrpc.SendMythicRPCCallbackUpdate(update); err != nil {
					logging.LogError(err, "Failed to update callback metadata from sysinfo")
				}
			}
			return response
		},
		TaskFunctionOPSECPre: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTTaskOPSECPreTaskMessageResponse {
			return agentstructs.PTTTaskOPSECPreTaskMessageResponse{
				TaskID:             taskData.Task.ID,
				Success:            true,
				OpsecPreBlocked:    false,
				OpsecPreMessage:    "OPSEC WARNING: System information discovery collects OS version, hardware details, hostname, domain, and network configuration. Standard reconnaissance footprint — commonly baselined by EDR.",
				OpsecPreBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionOPSECPost: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskOPSECPostTaskMessageResponse {
			return agentstructs.PTTaskOPSECPostTaskMessageResponse{
				TaskID:              taskData.Task.ID,
				Success:             true,
				OpsecPostBlocked:    false,
				OpsecPostMessage:    "OPSEC AUDIT: System information collected. Comprehensive system enumeration reveals OS version, hardware, domain membership. WMI queries may be logged by EDR.",
				OpsecPostBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionCreateTasking: func(task *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			return agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  task.Task.ID,
			}
		},
	})
}

// extractField extracts the value after a "Key:" prefix from a trimmed line.
func extractField(line, prefix string) string {
	if strings.HasPrefix(line, prefix) {
		return strings.TrimSpace(strings.TrimPrefix(line, prefix))
	}
	return ""
}
