package agentfunctions

import (
	"encoding/json"
	"fmt"
	"path/filepath"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name: "auditpol",
		AssociatedBrowserScript: &agentstructs.BrowserScript{
			ScriptPath: filepath.Join(".", "fawkes", "browserscripts", "auditpol_new.js"),
			Author:     "@galoryber",
		},
		Description:         "Query and modify Windows audit policies — disable security event logging before sensitive operations, re-enable after. Uses AuditQuerySystemPolicy/AuditSetSystemPolicy API (no auditpol.exe process creation).",
		HelpString:          "auditpol -action <query|disable|enable|stealth> [-category <name|all>]",
		Version:             1,
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1562.002"}, // Impair Defenses: Disable Windows Event Logging
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
				Choices:       []string{"query", "disable", "enable", "stealth"},
				DefaultValue:  "query",
				Description:   "Action: query (show current policies), disable (turn off auditing), enable (turn on success+failure), stealth (disable detection-critical subcategories)",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     1,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:          "category",
				CLIName:       "category",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:  "",
				Description:   "Category or subcategory name to target (e.g., 'Logon/Logoff', 'Process Creation', 'all'). Required for disable/enable. Stealth targets predefined detection-critical subcategories.",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     2,
						GroupName:           "Default",
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
				TaskID: taskData.Task.ID, Success: true,
				OpsecPreBlocked: false,
				OpsecPreMessage:    "OPSEC WARNING: Modifying audit policy (T1562.002). Changing audit categories disables security event logging. This is a high-confidence defense evasion indicator that SIEM systems specifically alert on.",
				OpsecPreBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
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
			type auditEntry struct {
				Category    string `json:"category"`
				Subcategory string `json:"subcategory"`
				Setting     string `json:"setting"`
			}
			var entries []auditEntry
			if err := json.Unmarshal([]byte(responseText), &entries); err != nil {
				return response
			}
			for _, e := range entries {
				if e.Setting == "No Auditing" {
					createArtifact(processResponse.TaskData.Task.ID, "Configuration",
						fmt.Sprintf("Audit disabled: %s/%s", e.Category, e.Subcategory))
				}
			}
			return response
		},
		TaskFunctionOPSECPost: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskOPSECPostTaskMessageResponse {
			return agentstructs.PTTaskOPSECPostTaskMessageResponse{
				TaskID:              taskData.Task.ID,
				Success:             true,
				OpsecPostBlocked:    false,
				OpsecPostMessage:    "OPSEC AUDIT: Audit policy enumeration completed. Results reveal which events are being logged — disabled categories indicate blind spots. Querying audit policy via AuditQuerySystemPolicy is itself a low-noise operation but the intelligence gained directly informs evasion strategy.",
				OpsecPostBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionCreateTasking: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  taskData.Task.ID,
			}
			action, _ := taskData.Args.GetStringArg("action")
			category, _ := taskData.Args.GetStringArg("category")

			display := action
			if category != "" {
				display += fmt.Sprintf(" %s", category)
			}
			response.DisplayParams = &display

			if action != "query" {
				msg := fmt.Sprintf("AuditSetSystemPolicy — %s", action)
				if category != "" {
					msg += fmt.Sprintf(" (category: %s)", category)
				}
				createArtifact(taskData.Task.ID, "API Call", msg)
			}
			return response
		},
	})
}
