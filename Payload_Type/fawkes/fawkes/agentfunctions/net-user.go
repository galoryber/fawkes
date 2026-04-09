package agentfunctions

import (
	"fmt"
	"path/filepath"
	"strings"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name: "net-user",
		AssociatedBrowserScript: &agentstructs.BrowserScript{
			ScriptPath: filepath.Join(".", "fawkes", "browserscripts", "netuser_new.js"),
			Author:     "@galoryber",
		},
		Description:         "Manage local user accounts and group membership (T1136.001, T1098). Windows: Win32 NetUser API. Linux: useradd/userdel/usermod/chpasswd. macOS: dscl/dseditgroup.",
		HelpString:          "net-user -action <add|delete|info|password|group-add|group-remove|disable|enable|lockout> -username <name> [-password <pass>] [-group <group>]",
		Version:             4,
		SupportedUIFeatures: []string{},
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1136.001", "T1098", "T1531"},
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
				Choices:          []string{"add", "delete", "info", "password", "group-add", "group-remove", "disable", "enable", "lockout"},
				Description:      "Action to perform",
				DefaultValue:     "info",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: true,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:                 "username",
				ModalDisplayName:     "Username",
				CLIName:              "username",
				ParameterType:        agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:          "Target username",
				DynamicQueryFunction: getCallbackUserList,
				DefaultValue:         "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: true,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "password",
				ModalDisplayName: "Password",
				CLIName:          "password",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Password (required for add and password actions)",
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "group",
				ModalDisplayName: "Group",
				CLIName:          "group",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Local group name (required for group-add and group-remove actions)",
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "comment",
				ModalDisplayName: "Comment",
				CLIName:          "comment",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Account comment/description (optional, for add action)",
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
		},
		TaskFunctionOPSECPre: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTTaskOPSECPreTaskMessageResponse {
			action, _ := taskData.Args.GetStringArg("action")
			username, _ := taskData.Args.GetStringArg("username")
			var msg string
			switch action {
			case "add":
				msg = fmt.Sprintf("OPSEC WARNING: Creating local user account '%s' (T1136.001). Account creation generates Windows Security Event 4720 and is highly monitored by SIEM/EDR.", username)
			case "delete":
				msg = fmt.Sprintf("OPSEC WARNING: Deleting local user account '%s' (T1098). Account deletion generates Windows Security Event 4726 and may trigger incident response.", username)
			case "password":
				msg = fmt.Sprintf("OPSEC WARNING: Changing password for '%s' (T1098). Password changes generate Windows Security Event 4724 and are monitored by identity protection systems.", username)
			case "group-add", "group-remove":
				group, _ := taskData.Args.GetStringArg("group")
				msg = fmt.Sprintf("OPSEC WARNING: Modifying group membership for '%s' in '%s' (T1098). Group changes generate Security Events 4732/4733 and are monitored for privilege escalation.", username, group)
			case "disable":
				msg = fmt.Sprintf("OPSEC CRITICAL: Disabling account '%s' (T1531 Account Access Removal). Generates Security Event 4725 and impacts service availability. This is a DESTRUCTIVE operation used in ransomware simulation.", username)
			case "enable":
				msg = fmt.Sprintf("OPSEC WARNING: Re-enabling account '%s'. Generates Security Event 4722.", username)
			case "lockout":
				msg = fmt.Sprintf("OPSEC CRITICAL: Locking out account '%s' (T1531 Account Access Removal). Generates Security Event 4740. Account will be unable to authenticate until policy-based auto-unlock or manual unlock.", username)
			default:
				msg = fmt.Sprintf("OPSEC WARNING: User account query for '%s' — low detection risk.", username)
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
			username, _ := taskData.Args.GetStringArg("username")
			display := fmt.Sprintf("%s user: %s", action, username)
			response.DisplayParams = &display
			osType := taskData.Callback.OS
			switch action {
			case "add":
				switch osType {
				case "Linux":
					createArtifact(taskData.Task.ID, "Process Create", fmt.Sprintf("useradd -m -s /bin/bash %s", username))
				case "macOS":
					createArtifact(taskData.Task.ID, "Process Create", fmt.Sprintf("dscl . -create /Users/%s", username))
				default:
					createArtifact(taskData.Task.ID, "API Call", fmt.Sprintf("NetUserAdd(%s)", username))
				}
			case "delete":
				switch osType {
				case "Linux":
					createArtifact(taskData.Task.ID, "Process Create", fmt.Sprintf("userdel -r %s", username))
				case "macOS":
					createArtifact(taskData.Task.ID, "Process Create", fmt.Sprintf("dscl . -delete /Users/%s", username))
				default:
					createArtifact(taskData.Task.ID, "API Call", fmt.Sprintf("NetUserDel(%s)", username))
				}
			case "password":
				switch osType {
				case "Linux":
					createArtifact(taskData.Task.ID, "Process Create", fmt.Sprintf("chpasswd (user: %s)", username))
				case "macOS":
					createArtifact(taskData.Task.ID, "Process Create", fmt.Sprintf("dscl . -passwd /Users/%s", username))
				default:
					createArtifact(taskData.Task.ID, "API Call", fmt.Sprintf("NetUserSetInfo(%s, level=1003)", username))
				}
			case "group-add":
				group, _ := taskData.Args.GetStringArg("group")
				switch osType {
				case "Linux":
					createArtifact(taskData.Task.ID, "Process Create", fmt.Sprintf("usermod -aG %s %s", group, username))
				case "macOS":
					createArtifact(taskData.Task.ID, "Process Create", fmt.Sprintf("dseditgroup -o edit -a %s -t user %s", username, group))
				default:
					createArtifact(taskData.Task.ID, "API Call", fmt.Sprintf("NetLocalGroupAddMembers(%s, %s)", group, username))
				}
			case "group-remove":
				group, _ := taskData.Args.GetStringArg("group")
				switch osType {
				case "Linux":
					createArtifact(taskData.Task.ID, "Process Create", fmt.Sprintf("gpasswd -d %s %s", username, group))
				case "macOS":
					createArtifact(taskData.Task.ID, "Process Create", fmt.Sprintf("dseditgroup -o edit -d %s -t user %s", username, group))
				default:
					createArtifact(taskData.Task.ID, "API Call", fmt.Sprintf("NetLocalGroupDelMembers(%s, %s)", group, username))
				}
			case "disable":
				createArtifact(taskData.Task.ID, "API Call", fmt.Sprintf("NetUserSetInfo(%s, UF_ACCOUNTDISABLE)", username))
				logOperationEvent(taskData.Task.ID,
					fmt.Sprintf("[IMPACT] net-user disable %s on %s (T1531)", username, taskData.Callback.Host), true)
			case "enable":
				createArtifact(taskData.Task.ID, "API Call", fmt.Sprintf("NetUserSetInfo(%s, clear UF_ACCOUNTDISABLE)", username))
			case "lockout":
				createArtifact(taskData.Task.ID, "API Call", fmt.Sprintf("NetUserSetInfo(%s, UF_LOCKOUT)", username))
				logOperationEvent(taskData.Task.ID,
					fmt.Sprintf("[IMPACT] net-user lockout %s on %s (T1531)", username, taskData.Callback.Host), true)
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
			username, _ := processResponse.TaskData.Args.GetStringArg("username")
			switch action {
			case "add":
				if strings.Contains(responseText, "successfully") || strings.Contains(responseText, "created") {
					createArtifact(processResponse.TaskData.Task.ID, "Account Management",
						fmt.Sprintf("[User Created] %s", username))
				}
			case "delete":
				if strings.Contains(responseText, "successfully") || strings.Contains(responseText, "deleted") {
					createArtifact(processResponse.TaskData.Task.ID, "Account Management",
						fmt.Sprintf("[User Deleted] %s", username))
				}
			case "group-add":
				group, _ := processResponse.TaskData.Args.GetStringArg("group")
				if strings.Contains(responseText, "successfully") || strings.Contains(responseText, "added") {
					createArtifact(processResponse.TaskData.Task.ID, "Account Management",
						fmt.Sprintf("[Group Membership] %s added to %s", username, group))
				}
			case "disable":
				if strings.Contains(responseText, "disabled") {
					createArtifact(processResponse.TaskData.Task.ID, "Account Management",
						fmt.Sprintf("[Account Disabled] %s (T1531)", username))
				}
			case "enable":
				if strings.Contains(responseText, "enabled") {
					createArtifact(processResponse.TaskData.Task.ID, "Account Management",
						fmt.Sprintf("[Account Enabled] %s", username))
				}
			case "lockout":
				if strings.Contains(responseText, "locked out") {
					createArtifact(processResponse.TaskData.Task.ID, "Account Management",
						fmt.Sprintf("[Account Locked Out] %s (T1531)", username))
				}
			}
			return response
		},
	})
}
