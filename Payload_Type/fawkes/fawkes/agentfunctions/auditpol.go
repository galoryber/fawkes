package agentfunctions

import (
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
						GroupName:            "Default",
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
						GroupName:            "Default",
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
