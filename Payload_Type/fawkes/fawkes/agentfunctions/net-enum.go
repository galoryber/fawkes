package agentfunctions

import (
	"encoding/json"
	"fmt"
	"path/filepath"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name: "net-enum",
		AssociatedBrowserScript: &agentstructs.BrowserScript{
			ScriptPath: filepath.Join(".", "fawkes", "browserscripts", "netenum_new.js"),
			Author:     "@galoryber",
		},
		Description:         "Unified Windows network enumeration — users, groups, shares, sessions, logons, domain info via Win32 API",
		HelpString:          "net-enum -action <users|localgroups|groupmembers|admins|domainusers|domaingroups|domaininfo|loggedon|sessions|shares|mapped> [-target <host>] [-group <name>]",
		Version:             2,
		SupportedUIFeatures: []string{},
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1087.001", "T1087.002", "T1069.001", "T1069.002", "T1033", "T1049", "T1135"},
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
				Choices:          []string{"users", "localgroups", "groupmembers", "admins", "domainusers", "domaingroups", "domaininfo", "loggedon", "sessions", "shares", "mapped"},
				Description:      "Enumeration action: users/localgroups/groupmembers/admins (local), domainusers/domaingroups/domaininfo (domain), loggedon/sessions/shares/mapped (network)",
				DefaultValue:     "users",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: true,
						UIModalPosition:     1,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "target",
				ModalDisplayName: "Target Host",
				CLIName:          "target",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Remote hostname or IP (blank = local machine). For groupmembers: also used as group name if -group is not set.",
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     2,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "group",
				ModalDisplayName: "Group Name",
				CLIName:          "group",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Group name for groupmembers/admins actions (e.g., Administrators, 'Remote Desktop Users')",
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     3,
						GroupName:           "Default",
					},
				},
			},
		},
		TaskFunctionOPSECPre: nil,
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
			target, _ := taskData.Args.GetStringArg("target")
			group, _ := taskData.Args.GetStringArg("group")

			display := fmt.Sprintf("action: %s", action)
			if target != "" {
				display += fmt.Sprintf(", target: %s", target)
			}
			if group != "" {
				display += fmt.Sprintf(", group: %s", group)
			}
			response.DisplayParams = &display

			apiMap := map[string]string{
				"users":        "NetUserEnum",
				"localgroups":  "NetLocalGroupEnum",
				"groupmembers": "NetLocalGroupGetMembers",
				"admins":       "NetLocalGroupGetMembers(Administrators)",
				"domainusers":  "NetUserEnum(DC)",
				"domaingroups": "NetGroupEnum(DC)",
				"domaininfo":   "DsGetDcNameW",
				"loggedon":     "NetWkstaUserEnum",
				"sessions":     "NetSessionEnum",
				"shares":       "NetShareEnum",
				"mapped":       "WNetEnumResource",
			}
			apiName := apiMap[action]
			if apiName == "" {
				apiName = "NetAPI:" + action
			}
			msg := apiName
			if target != "" {
				msg += "(" + target + ")"
			}
			createArtifact(taskData.Task.ID, "API Call", msg)
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
			// Try to parse as JSON array of entries (users, groups, sessions, shares, etc.)
			var entries []struct {
				Name    string `json:"name"`
				Type    string `json:"type,omitempty"`
				Comment string `json:"comment,omitempty"`
				Domain  string `json:"domain,omitempty"`
			}
			if err := json.Unmarshal([]byte(responseText), &entries); err == nil && len(entries) > 0 {
				for _, e := range entries {
					desc := e.Name
					if e.Type != "" {
						desc += " (" + e.Type + ")"
					}
					if e.Domain != "" {
						desc += " [" + e.Domain + "]"
					}
					createArtifact(processResponse.TaskData.Task.ID, "Host Discovery", desc)
				}
				return response
			}
			// Try to parse as domaininfo struct
			var domInfo struct {
				DCName    string `json:"dc_name"`
				DCAddress string `json:"dc_address"`
				Domain    string `json:"domain"`
				Forest    string `json:"forest"`
			}
			if err := json.Unmarshal([]byte(responseText), &domInfo); err == nil && domInfo.Domain != "" {
				createArtifact(processResponse.TaskData.Task.ID, "Host Discovery",
					fmt.Sprintf("Domain: %s, DC: %s (%s), Forest: %s", domInfo.Domain, domInfo.DCName, domInfo.DCAddress, domInfo.Forest))
			}
			return response
		},
	})
}
