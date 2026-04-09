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
		Name:                "env-scan",
		Description:         "Scan process environment variables for leaked credentials, API keys, and secrets (T1057/T1552.001)",
		HelpString:          "env-scan [-pid <PID>] [-filter <pattern>]",
		Version:             1,
		SupportedUIFeatures: []string{},
		Author:              "@galoryber",
		AssociatedBrowserScript: &agentstructs.BrowserScript{
			ScriptPath: filepath.Join(".", "fawkes", "browserscripts", "env_scan_new.js"),
			Author:     "@galoryber",
		},
		MitreAttackMappings: []string{"T1057", "T1552.001"},
		ScriptOnlyCommand:   false,
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_LINUX, agentstructs.SUPPORTED_OS_MACOS},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:                 "pid",
				ModalDisplayName:     "PID",
				CLIName:              "pid",
				ParameterType:        agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:          "Target process ID. If 0 or omitted, scans all accessible processes.",
				DynamicQueryFunction: getProcessList,
				DefaultValue:         "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "filter",
				ModalDisplayName: "Filter",
				CLIName:          "filter",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Filter results by variable name or category pattern (case-insensitive).",
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
		},
		TaskFunctionParseArgString: func(args *agentstructs.PTTaskMessageArgsData, input string) error {
			if input == "" {
				return nil
			}
			// Try JSON first, fall back to plain text filter
			if err := args.LoadArgsFromJSONString(input); err != nil {
				args.SetArgValue("filter", input)
			}
			return nil
		},
		TaskFunctionParseArgDictionary: func(args *agentstructs.PTTaskMessageArgsData, input map[string]interface{}) error {
			return args.LoadArgsFromDictionary(input)
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
			// Parse env_scan output: "  [PID N] process: VARIABLE = value"
			re := regexp.MustCompile(`\[PID \d+\]\s+(\S+):\s+(\S+)\s+=\s+(.+)`)
			var creds []mythicrpc.MythicRPCCredentialCreateCredentialData
			for _, line := range strings.Split(responseText, "\n") {
				m := re.FindStringSubmatch(strings.TrimSpace(line))
				if m == nil {
					continue
				}
				process, varName, value := m[1], m[2], strings.TrimSpace(m[3])
				if value == "" || value == "(empty)" {
					continue
				}
				creds = append(creds, mythicrpc.MythicRPCCredentialCreateCredentialData{
					CredentialType: "plaintext",
					Realm:          process,
					Account:        varName,
					Credential:     value,
					Comment:        "env-scan (environment variable)",
				})
			}
			registerCredentials(processResponse.TaskData.Task.ID, creds)
			return response
		},
		TaskFunctionOPSECPre: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTTaskOPSECPreTaskMessageResponse {
			return agentstructs.PTTTaskOPSECPreTaskMessageResponse{
				TaskID: taskData.Task.ID, Success: true,
				OpsecPreBlocked: false,
				OpsecPreMessage:    "OPSEC WARNING: Scans process environment variables for leaked credentials and API keys (T1057, T1552.001). Reading other process memory/environment is monitored by EDR. Credential scanning patterns are a known attacker behavior.",
				OpsecPreBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionCreateTasking: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  taskData.Task.ID,
			}
			pid, _ := parsePIDFromArg(taskData)
			filter, _ := taskData.Args.GetStringArg("filter")
			display := "scan all"
			if pid > 0 {
				display = fmt.Sprintf("pid %d", pid)
			}
			if filter != "" {
				display += fmt.Sprintf(" (filter: %s)", filter)
			}
			response.DisplayParams = &display
			return response
		},
	})
}
