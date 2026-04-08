package agentfunctions

import (
	"fmt"
	"path/filepath"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name: "last",
		AssociatedBrowserScript: &agentstructs.BrowserScript{
			ScriptPath: filepath.Join(".", "fawkes", "browserscripts", "last_new.js"),
			Author:     "@galoryber",
		},
		Description:         "Show login history, failed login attempts, and system reboot events. Linux: parses wtmp/btmp/auth.log. Windows: queries Security/System event logs. macOS: uses last command + unified log.",
		HelpString:          "last\nlast -action logins -count 50\nlast -action failed -user admin\nlast -action reboot\nlogins: login history (default)\nfailed: failed login attempts\nreboot: system boot/shutdown/crash events",
		Version:             3,
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1087.001", "T1110", "T1082"},
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
				CLIName:          "action",
				ModalDisplayName: "Action",
				Description:      "logins: login history (default). failed: failed login attempts. reboot: system boot/shutdown/crash events.",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:          []string{"logins", "failed", "reboot"},
				DefaultValue:     "logins",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default", UIModalPosition: 0},
				},
			},
			{
				Name:          "count",
				CLIName:       "count",
				Description:   "Number of entries to show (default: 25)",
				DefaultValue:  25,
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default", UIModalPosition: 1},
				},
			},
			{
				Name:          "user",
				CLIName:       "user",
				Description:   "Filter by username",
				DefaultValue:  "",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default", UIModalPosition: 2},
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
			msg := "OPSEC WARNING: Login history enumeration. "
			if action == "failed" {
				msg += "Reading btmp (failed logins) enumerates attempted credentials and source IPs — may indicate reconnaissance to security monitoring."
			} else {
				msg += "Reading utmp/wtmp reveals active and historical user sessions. Account discovery activity may be flagged by EDR behavioral analytics."
			}
			return agentstructs.PTTTaskOPSECPreTaskMessageResponse{
				TaskID:             taskData.Task.ID,
				Success:            true,
				OpsecPreBlocked:    false,
				OpsecPreMessage:    msg,
				OpsecPreBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionCreateTasking: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{Success: true, TaskID: taskData.Task.ID}
			action, _ := taskData.Args.GetStringArg("action")
			count, _ := taskData.Args.GetNumberArg("count")
			user, _ := taskData.Args.GetStringArg("user")

			dp := action
			if user != "" {
				dp += fmt.Sprintf(", user: %s", user)
			}
			if count > 0 && int(count) != 25 {
				dp += fmt.Sprintf(", count: %d", int(count))
			}
			if dp != "" {
				response.DisplayParams = &dp
			}

			switch action {
			case "failed":
				createArtifact(taskData.Task.ID, "File Read", "/var/log/btmp")
			case "reboot":
				createArtifact(taskData.Task.ID, "File Read", "/var/log/wtmp")
				createArtifact(taskData.Task.ID, "Event Log Query", "System:6005,6006,6008,1074")
			default:
				createArtifact(taskData.Task.ID, "File Read", "/var/log/wtmp")
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
			action, _ := processResponse.TaskData.Args.GetStringArg("action")
			switch action {
			case "failed":
				logOperationEvent(processResponse.TaskData.Task.ID,
					"[DISCOVERY] Failed login history enumeration (T1087.001, T1110)", false)
			case "reboot":
				logOperationEvent(processResponse.TaskData.Task.ID,
					"[DISCOVERY] System reboot/shutdown history (T1082)", false)
			default:
				logOperationEvent(processResponse.TaskData.Task.ID,
					"[DISCOVERY] User login history enumeration (T1087.001)", false)
			}
			return response
		},
	})
}
