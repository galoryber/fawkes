package agentfunctions

import (
	"fmt"
	"path/filepath"
	"strings"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "usn-jrnl",
		Description:         "Query or delete the NTFS USN Change Journal for anti-forensics. Destroys file operation history used in forensic timeline reconstruction.",
		HelpString:          "usn-jrnl -action query\nusn-jrnl -action recent [-volume D:]\nusn-jrnl -action delete [-volume C:]",
		Version:             1,
		SupportedUIFeatures: []string{},
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1070.004"}, // Indicator Removal: File Deletion
		AssociatedBrowserScript: &agentstructs.BrowserScript{
			ScriptPath: filepath.Join(".", "fawkes", "browserscripts", "usnjrnl_new.js"),
			Author:     "@galoryber",
		},
		ScriptOnlyCommand: false,
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_WINDOWS},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:             "action",
				ModalDisplayName: "Action",
				CLIName:          "action",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Description:      "Action: query (show journal metadata), recent (last 100 records), delete (destroy journal)",
				DefaultValue:     "query",
				Choices:          []string{"query", "recent", "delete"},
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: true,
						GroupName:           "Default",
						UIModalPosition:     0,
					},
				},
			},
			{
				Name:             "volume",
				ModalDisplayName: "Volume",
				CLIName:          "volume",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Volume letter (default: C:)",
				DefaultValue:     "C:",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
						UIModalPosition:     1,
					},
				},
			},
		},
		TaskFunctionParseArgString: func(args *agentstructs.PTTaskMessageArgsData, input string) error {
			if input != "" {
				return args.LoadArgsFromJSONString(input)
			}
			return nil
		},
		TaskFunctionParseArgDictionary: func(args *agentstructs.PTTaskMessageArgsData, input map[string]interface{}) error {
			return args.LoadArgsFromDictionary(input)
		},
		TaskFunctionOPSECPre: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTTaskOPSECPreTaskMessageResponse {
			action, _ := taskData.Args.GetStringArg("action")
			msg := "OPSEC WARNING: USN Journal operations. "
			if action == "delete" {
				msg += "Deleting the USN Journal destroys file change history — this is an anti-forensics indicator that may trigger EDR/SIEM alerts."
			} else {
				msg += "Reading USN Journal via DeviceIoControl (FSCTL_QUERY_USN_JOURNAL). Direct NTFS metadata access may be flagged by behavioral analytics."
			}
			return agentstructs.PTTTaskOPSECPreTaskMessageResponse{
				TaskID:             taskData.Task.ID,
				Success:            true,
				OpsecPreBlocked:    false,
				OpsecPreMessage:    msg,
				OpsecPreBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionOPSECPost: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskOPSECPostTaskMessageResponse {
			return agentstructs.PTTaskOPSECPostTaskMessageResponse{
				TaskID:              taskData.Task.ID,
				Success:             true,
				OpsecPostBlocked:    false,
				OpsecPostMessage:    "OPSEC AUDIT: USN Journal analysis completed. Direct NTFS journal access via DeviceIoControl(FSCTL_READ_USN_JOURNAL) is an unusual operation that EDR may flag. Journal data reveals file creation/deletion/rename history — powerful for forensics but also reveals your own file operations if not careful.",
				OpsecPostBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionCreateTasking: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  taskData.Task.ID,
			}
			action, _ := taskData.Args.GetStringArg("action")
			volume, _ := taskData.Args.GetStringArg("volume")
			if volume == "" {
				volume = "C:"
			}
			switch action {
			case "delete":
				createArtifact(taskData.Task.ID, "API Call",
					"DeviceIoControl(FSCTL_DELETE_USN_JOURNAL, "+volume+")")
			default:
				createArtifact(taskData.Task.ID, "API Call",
					"DeviceIoControl(FSCTL_QUERY_USN_JOURNAL, "+volume+")")
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
			// Parse USN journal entries (recent action: "TIMESTAMP  FILENAME  REASON")
			count := 0
			for _, line := range strings.Split(responseText, "\n") {
				trimmed := strings.TrimSpace(line)
				if trimmed == "" || strings.HasPrefix(trimmed, "TIMESTAMP") || strings.HasPrefix(trimmed, "---") || strings.HasPrefix(trimmed, "Journal") || strings.HasPrefix(trimmed, "First") || strings.HasPrefix(trimmed, "Next") || strings.HasPrefix(trimmed, "Max") || strings.HasPrefix(trimmed, "Record") {
					continue
				}
				// Entry lines have timestamp + filename + reason
				parts := strings.Fields(trimmed)
				if len(parts) >= 3 {
					count++
					if count <= 20 { // Limit artifacts for large result sets
						createArtifact(processResponse.TaskData.Task.ID, "File Discovery",
							fmt.Sprintf("[USN Journal] %s", trimmed))
					}
				}
			}
			if count > 20 {
				createArtifact(processResponse.TaskData.Task.ID, "File Discovery",
					fmt.Sprintf("[USN Journal] ... and %d more records", count-20))
			}
			return response
		},
	})
}
