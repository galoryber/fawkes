package agentfunctions

import (
	"encoding/json"
	"fmt"
	"path/filepath"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name: "prefetch",
		AssociatedBrowserScript: &agentstructs.BrowserScript{
			ScriptPath: filepath.Join(".", "fawkes", "browserscripts", "prefetch_new.js"),
			Author:     "@galoryber",
		},
		Description:         "Parse and manage Windows Prefetch files — list executed programs, parse execution history, delete specific entries, or clear all. Supports compressed (MAM) prefetch files on Windows 10/11.",
		HelpString:          "prefetch -action <list|parse|delete|clear> [-name <exe_name>] [-count <max>]",
		Version:             1,
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1070.004"}, // Indicator Removal: File Deletion
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
				Choices:       []string{"list", "parse", "delete", "clear"},
				DefaultValue:  "list",
				Description:   "Action: list (show recent), parse (detailed info), delete (remove specific), clear (remove all)",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     1,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:          "name",
				CLIName:       "name",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:  "",
				Description:   "Executable name to filter/target (e.g., 'CMD.EXE', 'POWERSHELL'). Used with list, parse, and delete actions.",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     2,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:          "count",
				CLIName:       "count",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				DefaultValue:  50,
				Description:   "Maximum number of entries to show (default: 50)",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     3,
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
			action, _ := taskData.Args.GetStringArg("action")
			msg := "OPSEC WARNING: Prefetch forensic operations. "
			switch action {
			case "delete", "clear":
				msg += "Deleting prefetch files is an anti-forensics indicator — may trigger EDR alerts for evidence destruction."
			default:
				msg += "Reading prefetch files from C:\\Windows\\Prefetch reveals program execution history. File access may be audited."
			}
			return agentstructs.PTTTaskOPSECPreTaskMessageResponse{
				TaskID:             taskData.Task.ID,
				Success:            true,
				OpsecPreBlocked:    false,
				OpsecPreMessage:    msg,
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
			type prefetchEntry struct {
				Executable string `json:"executable"`
				RunCount   int    `json:"run_count"`
				LastRun    string `json:"last_run"`
				FileSize   int64  `json:"file_size"`
				Hash       string `json:"hash"`
			}
			var entries []prefetchEntry
			if err := json.Unmarshal([]byte(responseText), &entries); err != nil {
				return response
			}
			for _, e := range entries {
				createArtifact(processResponse.TaskData.Task.ID, "Execution Evidence",
					fmt.Sprintf("Prefetch: %s (run count: %d, last: %s)", e.Executable, e.RunCount, e.LastRun))
			}
			return response
		},
		TaskFunctionOPSECPost: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskOPSECPostTaskMessageResponse {
			return agentstructs.PTTaskOPSECPostTaskMessageResponse{
				TaskID:              taskData.Task.ID,
				Success:             true,
				OpsecPostBlocked:    false,
				OpsecPostMessage:    "OPSEC AUDIT: Prefetch analysis completed. Accessed C:\\Windows\\Prefetch directory — file access timestamps on .pf files updated. Prefetch data reveals execution history including timestamps and run counts. Note: your own agent's prefetch entry may now exist if not running from memory.",
				OpsecPostBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionCreateTasking: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  taskData.Task.ID,
			}
			action, _ := taskData.Args.GetStringArg("action")
			name, _ := taskData.Args.GetStringArg("name")

			display := action
			if name != "" {
				display += fmt.Sprintf(" %s", name)
			}
			response.DisplayParams = &display

			if action == "delete" || action == "clear" {
				msg := fmt.Sprintf("Prefetch file deletion: %s", action)
				if name != "" {
					msg += fmt.Sprintf(" (filter: %s)", name)
				}
				createArtifact(taskData.Task.ID, "File Delete", msg)
			}
			return response
		},
	})
}
