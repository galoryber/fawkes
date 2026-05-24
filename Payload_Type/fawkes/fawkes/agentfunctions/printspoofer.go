package agentfunctions

import (
	"path/filepath"
	"strconv"
	"strings"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "printspoofer",
		Description:         "PrintSpoofer privilege escalation — SeImpersonate to SYSTEM via Print Spooler named pipe impersonation (T1134.001)",
		HelpString:          "printspoofer [-timeout 15]",
		Version:             1,
		SupportedUIFeatures: []string{},
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1134.001"},
		ScriptOnlyCommand:   false,
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_WINDOWS},
			FilterCommandAvailabilityByAgentBuildParameters: map[string]string{"selected_os": "Windows"},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:             "timeout",
				ModalDisplayName: "Timeout (seconds)",
				CLIName:          "timeout",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				Description:      "How long to wait for the spooler to connect (default: 15 seconds)",
				DefaultValue:     15,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
		},
		AssociatedBrowserScript: &agentstructs.BrowserScript{ScriptPath: filepath.Join(".", "fawkes", "browserscripts", "printspoofer_new.js"), Author: "@galoryber"},
		TaskFunctionParseArgString: func(args *agentstructs.PTTaskMessageArgsData, input string) error {
			if input == "" {
				return nil
			}
			if err := args.LoadArgsFromJSONString(input); err == nil {
				return nil
			}
			// Plain text: parse -timeout N or just a number
			parts := strings.Fields(input)
			for i := 0; i < len(parts); i++ {
				if parts[i] == "-timeout" && i+1 < len(parts) {
					i++
					if t, err := strconv.Atoi(parts[i]); err == nil {
						args.SetArgValue("timeout", t)
					}
				} else if t, err := strconv.Atoi(parts[i]); err == nil {
					args.SetArgValue("timeout", t)
				}
			}
			return nil
		},
		TaskFunctionParseArgDictionary: func(args *agentstructs.PTTaskMessageArgsData, input map[string]interface{}) error {
			return args.LoadArgsFromDictionary(input)
		},
		TaskFunctionOPSECPre: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTTaskOPSECPreTaskMessageResponse {
			return agentstructs.PTTTaskOPSECPreTaskMessageResponse{
				TaskID: taskData.Task.ID, Success: true,
				OpsecPreBlocked: false,
				OpsecPreMessage:    "OPSEC WARNING: Exploiting SeImpersonatePrivilege for SYSTEM escalation (T1134.001). Named pipe impersonation via Print Spooler is a well-known privilege escalation technique detected by EDR behavioral rules.",
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
			if strings.Contains(responseText, "SYSTEM") || strings.Contains(responseText, "success") {
				createArtifact(processResponse.TaskData.Task.ID, "Privilege Escalation",
					"printspoofer: escalated to SYSTEM via SeImpersonate")
			}
			return response
		},
		TaskFunctionOPSECPost: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskOPSECPostTaskMessageResponse {
			return agentstructs.PTTaskOPSECPostTaskMessageResponse{
				TaskID:              taskData.Task.ID,
				Success:             true,
				OpsecPostBlocked:    false,
				OpsecPostMessage:    "OPSEC AUDIT: PrintSpoofer privilege escalation executed. SeImpersonatePrivilege was abused to obtain SYSTEM token via print spooler named pipe impersonation. New SYSTEM-level logon event (Event ID 4624 Type 3) created. EDR may flag named pipe impersonation patterns. Consider reverting to original token when SYSTEM access is no longer needed.",
				OpsecPostBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionCreateTasking: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  taskData.Task.ID,
			}
			display := "SeImpersonate → SYSTEM via Print Spooler"
			response.DisplayParams = &display
			createArtifact(taskData.Task.ID, "API Call", "Print Spooler named pipe impersonation (SeImpersonate → SYSTEM)")
			return response
		},
	})
}
