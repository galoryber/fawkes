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
		Name: "lateral-check",
		AssociatedBrowserScript: &agentstructs.BrowserScript{
			ScriptPath: filepath.Join(".", "fawkes", "browserscripts", "lateral_check_new.js"),
			Author:     "@galoryber",
		},
		Description:         "Test lateral movement options against target hosts (SMB, WinRM, RDP, RPC, SSH)",
		HelpString:          "lateral-check -hosts <IPs/CIDRs> [-timeout <seconds>]",
		Version:             1,
		SupportedUIFeatures: []string{},
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1046", "T1021"},
		ScriptOnlyCommand:   false,
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_LINUX, agentstructs.SUPPORTED_OS_MACOS, agentstructs.SUPPORTED_OS_WINDOWS},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:                 "hosts",
				ModalDisplayName:     "Target Hosts",
				CLIName:              "hosts",
				ParameterType:        agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:          "Single IP, comma-separated IPs, or CIDR range (e.g. 192.168.1.1, 10.0.0.0/24). Max 256 hosts.",
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
				Name:             "timeout",
				ModalDisplayName: "Timeout (seconds)",
				CLIName:          "timeout",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				Description:      "Per-check TCP connection timeout in seconds (default: 3)",
				DefaultValue:     3,
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
				return agentstructs.PTTTaskOPSECPreTaskMessageResponse{
					TaskID:             taskData.Task.ID,
					Success:            true,
					OpsecPreBlocked:    false,
					OpsecPreMessage:    fmt.Sprintf("OPSEC WARNING: Lateral movement check on %s probes SMB (445), WinRM (5985/5986), RDP (3389), SSH (22), and RPC (135). Generates connection attempts to multiple ports on each target. NDR and host-based firewalls will log these connection attempts.", hosts),
					OpsecPreBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
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
			display := fmt.Sprintf("targets: %s", hosts)
			response.DisplayParams = &display
			return response
		},
		TaskFunctionProcessResponse: func(processResponse agentstructs.PtTaskProcessResponseMessage) agentstructs.PTTaskProcessResponseMessageResponse {
			response := agentstructs.PTTaskProcessResponseMessageResponse{
				TaskID:  processResponse.TaskData.Task.ID,
				Success: true,
			}
			responseText, ok := processResponse.Response.(string)
			if !ok || responseText == "" || responseText == "[]" {
				return response
			}
			type lateralEntry struct {
				Host      string   `json:"host"`
				Available []string `json:"available"`
				TotalOpen int      `json:"total_open"`
				Suggested []string `json:"suggested"`
			}
			var entries []lateralEntry
			if err := json.Unmarshal([]byte(responseText), &entries); err != nil {
				return response
			}
			for _, e := range entries {
				if e.TotalOpen == 0 {
					continue
				}
				createArtifact(processResponse.TaskData.Task.ID, "Host Discovery",
					fmt.Sprintf("Lateral: %s — %s (suggested: %s)",
						e.Host, strings.Join(e.Available, ", "), strings.Join(e.Suggested, ", ")))
			}
			return response
		},
	})
}
