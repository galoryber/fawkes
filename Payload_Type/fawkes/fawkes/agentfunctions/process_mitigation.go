package agentfunctions

import (
	"fmt"
	"path/filepath"
	"strings"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "process-mitigation",
		Description:         "Query or set Windows process mitigation policies (DEP, ASLR, CIG, ACG, CFG). Set CIG to block unsigned DLL loading (EDR injection defense).",
		HelpString:          "process-mitigation\nprocess-mitigation -action query\nprocess-mitigation -action query -pid 1234\nprocess-mitigation -action set -policy cig",
		Version:             1,
		SupportedUIFeatures: []string{},
		Author:              "@galoryber",
		AssociatedBrowserScript: &agentstructs.BrowserScript{
			ScriptPath: filepath.Join(".", "fawkes", "browserscripts", "process_mitigation_new.js"),
			Author:     "@galoryber",
		},
		MitreAttackMappings: []string{"T1480"},
		ScriptOnlyCommand:   false,
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_WINDOWS},
			FilterCommandAvailabilityByAgentBuildParameters: map[string]string{"selected_os": "Windows"},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:             "action",
				ModalDisplayName: "Action",
				CLIName:          "action",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Description:      "query: list all mitigation policies. set: enable a specific policy on the current process.",
				DefaultValue:     "query",
				Choices:          []string{"query", "set"},
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
						UIModalPosition:     0,
					},
				},
			},
			{
				Name:                 "pid",
				ModalDisplayName:     "Target PID",
				CLIName:              "pid",
				ParameterType:        agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:          "Process ID to query (0 or omit for self). Only used with query action.",
				DynamicQueryFunction: getProcessList,
				DefaultValue:         "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
						UIModalPosition:     1,
					},
				},
			},
			{
				Name:             "policy",
				ModalDisplayName: "Policy to Set",
				CLIName:          "policy",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Description:      "Policy to enable (only used with set action). cig=block unsigned DLLs, acg=block dynamic code, child-block=prevent child processes.",
				DefaultValue:     "cig",
				Choices:          []string{"cig", "acg", "child-block", "dep", "cfg", "ext-disable", "image-restrict", "font-disable"},
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
						UIModalPosition:     2,
					},
				},
			},
		},
		TaskFunctionOPSECPost: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskOPSECPostTaskMessageResponse {
			action, _ := taskData.Args.GetStringArg("action")
			msg := "OPSEC AUDIT: Process mitigation policy query completed. Policy enumeration via GetProcessMitigationPolicy API generates process access events."
			if strings.EqualFold(action, "set") {
				policy, _ := taskData.Args.GetStringArg("policy")
				msg = fmt.Sprintf("OPSEC AUDIT: Process mitigation policy '%s' modification completed. SetProcessMitigationPolicy calls are monitored by EDR — policy changes to ACG, CIG, or child-process restrictions are defense evasion indicators.", policy)
			}
			return agentstructs.PTTaskOPSECPostTaskMessageResponse{
				TaskID:              taskData.Task.ID,
				Success:             true,
				OpsecPostBlocked:    false,
				OpsecPostMessage:    msg,
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
			return agentstructs.PTTTaskOPSECPreTaskMessageResponse{
				TaskID: taskData.Task.ID, Success: true,
				OpsecPreBlocked: false,
				OpsecPreMessage:    "OPSEC WARNING: Querying/modifying process mitigation policies (T1562). Reading mitigation status reveals security controls in place. Modifying policies (e.g., disabling CFG, ACG) is a defense evasion technique.",
				OpsecPreBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionCreateTasking: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  taskData.Task.ID,
			}
			action, _ := taskData.Args.GetStringArg("action")
			if action == "" {
				action = "query"
			}
			switch action {
			case "query":
				pid, _ := parsePIDFromArg(taskData)
				if pid > 0 {
					createArtifact(taskData.Task.ID, "API Call",
						fmt.Sprintf("GetProcessMitigationPolicy(PID %d)", pid))
				} else {
					createArtifact(taskData.Task.ID, "API Call",
						"GetProcessMitigationPolicy(self)")
				}
			case "set":
				policy, _ := taskData.Args.GetStringArg("policy")
				createArtifact(taskData.Task.ID, "API Call",
					fmt.Sprintf("SetProcessMitigationPolicy(%s)", policy))
			}
			if displayParams, err := taskData.Args.GetFinalArgs(); err == nil && displayParams != "" {
				response.DisplayParams = &displayParams
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
			// Parse process mitigation policy results (key: value lines)
			var enabled []string
			for _, line := range strings.Split(responseText, "\n") {
				trimmed := strings.TrimSpace(line)
				if strings.Contains(trimmed, ": true") || strings.Contains(trimmed, ": Enabled") {
					parts := strings.SplitN(trimmed, ":", 2)
					if len(parts) == 2 {
						enabled = append(enabled, strings.TrimSpace(parts[0]))
					}
				}
			}
			if len(enabled) > 0 {
				createArtifact(processResponse.TaskData.Task.ID, "Configuration",
					fmt.Sprintf("[Process Mitigation] Enabled policies: %s", strings.Join(enabled, ", ")))
			} else {
				createArtifact(processResponse.TaskData.Task.ID, "Configuration",
					"[Process Mitigation] No mitigation policies enabled")
			}
			return response
		},
	})
}
