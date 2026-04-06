package agentfunctions

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name: "security-info",
		AssociatedBrowserScript: &agentstructs.BrowserScript{
			ScriptPath: filepath.Join(".", "fawkes", "browserscripts", "securityinfo_new.js"),
			Author:     "@GlobeTech",
		},
		Description:         "Report security posture and active controls, or detect installed EDR/XDR products. Linux: SELinux, AppArmor, seccomp, ASLR, YAMA, LSM, BPF. macOS: SIP, Gatekeeper, FileVault, MDM, TCC, SSH, JAMF, ARD. Windows: Defender, Credential Guard, UAC, BitLocker, CLM.",
		HelpString:          "security-info [-action all|edr]",
		Version:             3,
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1082", "T1518.001"},
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
				ModalDisplayName: "Action",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Description:      "all: report security posture (default). edr: detect installed EDR/XDR/AV products.",
				Choices:          []string{"all", "edr"},
				DefaultValue:     "all",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
						UIModalPosition:     0,
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
				TaskID:             taskData.Task.ID,
				Success:            true,
				OpsecPreBlocked:    false,
				OpsecPreMessage:    "OPSEC WARNING: Security configuration extraction enumerates firewall rules, AV status, EDR products, and security policies. This is a common reconnaissance pattern that security monitoring tools specifically watch for.",
				OpsecPreBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionCreateTasking: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{Success: true, TaskID: taskData.Task.ID}
			action, _ := taskData.Args.GetStringArg("action")
			if action == "" {
				action = "all"
			}
			display := fmt.Sprintf("action: %s", action)
			response.DisplayParams = &display

			params := map[string]string{"action": action}
			paramsJSON, _ := json.Marshal(params)
			taskData.Args.SetManualArgs(string(paramsJSON))

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
			if action == "edr" {
				// Parse EDR detection JSON output and register detected products as artifacts
				// Output format: text header followed by JSON array of edrDetection objects
				jsonStart := strings.Index(responseText, "[")
				if jsonStart < 0 {
					return response
				}
				var detections []struct {
					Name    string `json:"name"`
					Vendor  string `json:"vendor"`
					Status  string `json:"status"`
					Process string `json:"process,omitempty"`
					PID     int    `json:"pid,omitempty"`
				}
				if err := json.Unmarshal([]byte(responseText[jsonStart:]), &detections); err != nil {
					return response
				}
				for _, d := range detections {
					if d.Status == "running" || d.Status == "installed" {
						detail := fmt.Sprintf("[EDR] %s (%s) — %s", d.Name, d.Vendor, d.Status)
						if d.Process != "" {
							detail += fmt.Sprintf(" (process: %s", d.Process)
							if d.PID > 0 {
								detail += fmt.Sprintf(", PID %d", d.PID)
							}
							detail += ")"
						}
						createArtifact(processResponse.TaskData.Task.ID, "Host Discovery", detail)
					}
				}
			}
			return response
		},
	})
}
