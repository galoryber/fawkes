package agentfunctions

import (
	"fmt"
	"strings"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "tscon",
		Description:         "RDP session management — list sessions, hijack, disconnect, logoff users",
		HelpString:          "tscon [-action <list|hijack|disconnect|logoff>] [-session_id <id>]",
		Version:             1,
		SupportedUIFeatures: []string{},
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1563.002"},
		ScriptOnlyCommand:   false,
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_WINDOWS},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:             "action",
				ModalDisplayName: "Action",
				CLIName:          "action",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Description:      "Action to perform",
				DefaultValue:     "list",
				Choices:          []string{"list", "hijack", "disconnect", "logoff"},
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "session_id",
				ModalDisplayName: "Session ID",
				CLIName:          "session_id",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				Description:      "Target RDP session ID (required for hijack/disconnect/logoff)",
				DefaultValue:     0,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
		},
		AssociatedBrowserScript: nil,
		TaskFunctionOPSECPre: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTTaskOPSECPreTaskMessageResponse {
			action, _ := taskData.Args.GetStringArg("action")
			var msg string
			switch action {
			case "hijack":
				msg = "OPSEC WARNING: RDP session hijacking (T1563.002). Session hijacking requires SYSTEM privileges and is detected by Windows Security Event 4778/4779. EDR products monitor for tscon.exe and WTSConnectSession API calls."
			case "disconnect", "logoff":
				msg = fmt.Sprintf("OPSEC WARNING: RDP session %s (T1563.002). Session manipulation generates Windows Security Events and may alert the target user.", action)
			default:
				msg = "OPSEC WARNING: RDP session enumeration (T1563.002). Session listing is low-risk but indicates reconnaissance of active users."
			}
			return agentstructs.PTTTaskOPSECPreTaskMessageResponse{
				TaskID: taskData.Task.ID, Success: true,
				OpsecPreBlocked:    false,
				OpsecPreMessage:    msg,
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
			action, _ := taskData.Args.GetStringArg("action")
			sessionID, _ := taskData.Args.GetNumberArg("session_id")
			display := fmt.Sprintf("%s session %d", action, int(sessionID))
			response.DisplayParams = &display
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
			if action == "hijack" && strings.Contains(responseText, "success") {
				sessionID, _ := processResponse.TaskData.Args.GetNumberArg("session_id")
				createArtifact(processResponse.TaskData.Task.ID, "Lateral Movement",
					fmt.Sprintf("[RDP Hijack] Session %d hijacked", int(sessionID)))
			} else if action == "list" {
				// Count sessions in output
				lineCount := 0
				for _, line := range strings.Split(responseText, "\n") {
					if strings.TrimSpace(line) != "" {
						lineCount++
					}
				}
				if lineCount > 1 {
					createArtifact(processResponse.TaskData.Task.ID, "Host Discovery",
						fmt.Sprintf("[RDP Sessions] %d sessions enumerated", lineCount-1))
				}
			}
			return response
		},
	})
}
