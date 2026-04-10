package agentfunctions

import (
	"encoding/json"
	"fmt"
	"path/filepath"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name: "logonsessions",
		AssociatedBrowserScript: &agentstructs.BrowserScript{
			ScriptPath: filepath.Join(".", "fawkes", "browserscripts", "logonsessions_new.js"),
			Author:     "@galoryber",
		},
		Description:         "Enumerate active logon sessions — shows who is logged in, session type, and logon time",
		HelpString:          "logonsessions [-action list|users] [-filter username]",
		Version:             2,
		SupportedUIFeatures: []string{},
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1033"},
		ScriptOnlyCommand:   false,
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_WINDOWS, agentstructs.SUPPORTED_OS_LINUX, agentstructs.SUPPORTED_OS_MACOS},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:             "action",
				ModalDisplayName: "Action",
				CLIName:          "action",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:          []string{"list", "users"},
				Description:      "list: show all logon sessions | users: show unique logged-on users",
				DefaultValue:     "list",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:                 "filter",
				ModalDisplayName:     "Username Filter",
				CLIName:              "filter",
				ParameterType:        agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:          "Optional: filter results by username or domain substring",
				DefaultValue:         "",
				DynamicQueryFunction: getCallbackUserList,
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
			msg := "OPSEC WARNING: Logon session enumeration. "
			switch taskData.Payload.OS {
			case "Windows":
				msg += "Calls LsaEnumerateLogonSessions + LsaGetLogonSessionData + WTSEnumerateSessionsW. Enumerating LSA logon sessions may be monitored by EDR."
			default:
				msg += "Reads utmp/utmpx files for active sessions. Low risk on Linux/macOS."
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
			// Try parsing as session list first
			type sessionEntry struct {
				SessionID string `json:"session_id"`
				Username  string `json:"username"`
				Domain    string `json:"domain"`
				Station   string `json:"station"`
				State     string `json:"state"`
				Client    string `json:"client"`
			}
			var sessions []sessionEntry
			if err := json.Unmarshal([]byte(responseText), &sessions); err == nil && len(sessions) > 0 && sessions[0].SessionID != "" {
				for _, s := range sessions {
					createArtifact(processResponse.TaskData.Task.ID, "Account Discovery",
						fmt.Sprintf("Logon: %s\\%s (session %s, state: %s)", s.Domain, s.Username, s.SessionID, s.State))
				}
				return response
			}
			// Fall back to user list
			type userEntry struct {
				User     string `json:"user"`
				Domain   string `json:"domain"`
				Sessions int    `json:"sessions"`
				Details  string `json:"details"`
			}
			var users []userEntry
			if err := json.Unmarshal([]byte(responseText), &users); err == nil {
				for _, u := range users {
					createArtifact(processResponse.TaskData.Task.ID, "Account Discovery",
						fmt.Sprintf("User: %s\\%s (%d sessions)", u.Domain, u.User, u.Sessions))
				}
			}
			return response
		},
		TaskFunctionOPSECPost: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskOPSECPostTaskMessageResponse {
			return agentstructs.PTTaskOPSECPostTaskMessageResponse{
				TaskID:              taskData.Task.ID,
				Success:             true,
				OpsecPostBlocked:    false,
				OpsecPostMessage:    "OPSEC AUDIT: Logon session enumeration completed. LsaEnumerateLogonSessions API call may be logged by EDR. Session data reveals active users, authentication types, and logon times — useful for lateral movement planning but also a detection indicator for credential access activity.",
				OpsecPostBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionCreateTasking: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  taskData.Task.ID,
			}
			action, _ := taskData.Args.GetStringArg("action")
			display := fmt.Sprintf("%s", action)
			response.DisplayParams = &display
			switch taskData.Payload.OS {
			case "Windows":
				createArtifact(taskData.Task.ID, "API Call", "LsaEnumerateLogonSessions + LsaGetLogonSessionData + WTSEnumerateSessionsW")
			case "macOS":
				createArtifact(taskData.Task.ID, "FileOpen", "/var/run/utmpx")
			default:
				createArtifact(taskData.Task.ID, "FileOpen", "/var/run/utmp")
			}
			return response
		},
	})
}
