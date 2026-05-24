package agentfunctions

import (
	"fmt"
	"path/filepath"
	"strings"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
	"github.com/MythicMeta/MythicContainer/mythicrpc"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "defender",
		Description:         "Manage Windows Defender — status, exclusions, threats, enable/disable real-time protection. Uses WMI and PowerShell.",
		HelpString:          "defender -action <status|exclusions|add-exclusion|remove-exclusion|threats|enable|disable> [-type <path|process|extension>] [-value <exclusion_value>]",
		Version:             1,
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1562.001"}, // Impair Defenses: Disable or Modify Tools
		AssociatedBrowserScript: &agentstructs.BrowserScript{
			ScriptPath: filepath.Join(".", "fawkes", "browserscripts", "defender_new.js"),
			Author:     "@galoryber",
		},
		SupportedUIFeatures: []string{},
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_WINDOWS},
			FilterCommandAvailabilityByAgentBuildParameters: map[string]string{"selected_os": "Windows"},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:          "action",
				CLIName:       "action",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:       []string{"status", "exclusions", "add-exclusion", "remove-exclusion", "threats", "enable", "disable"},
				DefaultValue:  "status",
				Description:   "Action: check status, list/add/remove exclusions, view threats, or enable/disable real-time protection",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: true,
						UIModalPosition:     1,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:          "type",
				CLIName:       "type",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:       []string{"path", "process", "extension"},
				DefaultValue:  "path",
				Description:   "Exclusion type: path, process, or extension (for add/remove-exclusion)",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     2,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:          "value",
				CLIName:       "value",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:  "",
				Description:   "Exclusion value (e.g., 'C:\\Users\\setup\\Downloads', 'payload.exe', '.dat')",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     3,
						GroupName:           "Default",
					},
				},
			},
		},
		TaskFunctionOPSECPost: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskOPSECPostTaskMessageResponse {
			return agentstructs.PTTaskOPSECPostTaskMessageResponse{
				TaskID:              taskData.Task.ID,
				Success:             true,
				OpsecPostBlocked:    false,
				OpsecPostMessage:    "OPSEC AUDIT: Windows Defender operation completed. Defender configuration changes generate Event ID 5001/5007 in Microsoft-Windows-Windows Defender/Operational. Exclusion additions and protection disabling are high-priority SOC alerts.",
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
		TaskFunctionOPSECPre: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTTaskOPSECPreTaskMessageResponse {
			action, _ := taskData.Args.GetStringArg("action")
			msg := fmt.Sprintf("OPSEC WARNING: Windows Defender interaction (action: %s). ", action)
			switch action {
			case "disable":
				msg += "Disabling real-time protection generates Event ID 5001 (Real-Time Protection disabled) and may trigger EDR alerts. Tamper Protection may block this operation."
			case "exclude":
				msg += "Adding exclusions generates Event ID 5007 (Defender configuration change). Exclusion paths are visible in the registry and commonly checked by analysts."
			case "remove":
				msg += "Threat removal generates defender event logs documenting the action."
			default:
				msg += "Read-only enumeration is lower risk but defender logs may record the query."
			}
			return agentstructs.PTTTaskOPSECPreTaskMessageResponse{
				TaskID:             taskData.Task.ID,
				Success:            true,
				OpsecPreBlocked:    false,
				OpsecPreMessage:    msg,
				OpsecPreBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionCreateTasking: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  taskData.Task.ID,
			}
			action, _ := taskData.Args.GetStringArg("action")
			value, _ := taskData.Args.GetStringArg("value")
			exType, _ := taskData.Args.GetStringArg("type")
			display := fmt.Sprintf("%s", action)
			response.DisplayParams = &display
			switch action {
			case "add-exclusion":
				mythicrpc.SendMythicRPCArtifactCreate(mythicrpc.MythicRPCArtifactCreateMessage{
					TaskID:           taskData.Task.ID,
					BaseArtifactType: "Registry Write",
					ArtifactMessage:  fmt.Sprintf("Defender %s exclusion added: %s", exType, value),
				})
			case "remove-exclusion":
				mythicrpc.SendMythicRPCArtifactCreate(mythicrpc.MythicRPCArtifactCreateMessage{
					TaskID:           taskData.Task.ID,
					BaseArtifactType: "Registry Write",
					ArtifactMessage:  fmt.Sprintf("Defender %s exclusion removed: %s", exType, value),
				})
			case "enable":
				createArtifact(taskData.Task.ID, "Process Create", "powershell.exe Set-MpPreference -DisableRealtimeMonitoring $false")
			case "disable":
				createArtifact(taskData.Task.ID, "Process Create", "powershell.exe Set-MpPreference -DisableRealtimeMonitoring $true")
			}
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
			action, _ := processResponse.TaskData.Args.GetStringArg("action")
			switch action {
			case "status":
				// Track Defender status for situational awareness
				if strings.Contains(responseText, "RealTimeProtection") || strings.Contains(responseText, "real_time") {
					status := "unknown"
					if strings.Contains(responseText, "Enabled") || strings.Contains(responseText, "true") {
						status = "enabled"
					} else if strings.Contains(responseText, "Disabled") || strings.Contains(responseText, "false") {
						status = "disabled"
					}
					createArtifact(processResponse.TaskData.Task.ID, "Host Discovery",
						fmt.Sprintf("[Defender] Real-time protection: %s", status))
				}
			case "exclusions":
				// Count exclusions for tracking
				exCount := 0
				for _, line := range strings.Split(responseText, "\n") {
					trimmed := strings.TrimSpace(line)
					if trimmed != "" && !strings.HasPrefix(trimmed, "=") && !strings.HasPrefix(trimmed, "-") &&
						(strings.Contains(trimmed, "\\") || strings.Contains(trimmed, "/") || strings.Contains(trimmed, ".")) {
						exCount++
					}
				}
				if exCount > 0 {
					createArtifact(processResponse.TaskData.Task.ID, "Host Discovery",
						fmt.Sprintf("[Defender] %d exclusions found", exCount))
				}
			case "threats":
				// Track detected threats
				for _, line := range strings.Split(responseText, "\n") {
					if strings.Contains(line, "ThreatName") || strings.Contains(line, "threat_name") {
						createArtifact(processResponse.TaskData.Task.ID, "Host Discovery",
							fmt.Sprintf("[Defender] Threat detected: %s", strings.TrimSpace(line)))
					}
				}
			case "disable":
				if strings.Contains(responseText, "disabled") || strings.Contains(responseText, "Disabled") || strings.Contains(responseText, "Success") {
					createArtifact(processResponse.TaskData.Task.ID, "API Call",
						"[Defender] Real-time protection disabled")
				}
			case "enable":
				if strings.Contains(responseText, "enabled") || strings.Contains(responseText, "Enabled") || strings.Contains(responseText, "Success") {
					createArtifact(processResponse.TaskData.Task.ID, "API Call",
						"[Defender] Real-time protection enabled")
				}
			}
			return response
		},
	})
}
