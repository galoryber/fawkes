package agentfunctions

import (
	"fmt"
	"strings"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "runas",
		Description:         "Execute a command as a different user. Windows: CreateProcessWithLogonW. Linux/macOS: setuid (as root) or sudo -S (with password). (T1134.002)",
		HelpString:          "runas -command <cmd> -username <user> -password <pass> [-domain <domain>] [-netonly true]",
		Version:             2,
		SupportedUIFeatures: []string{},
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1134.002"},
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
				Name:             "command",
				ModalDisplayName: "Command",
				CLIName:          "command",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Command line to execute (e.g. cmd.exe /c whoami)",
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: true,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "username",
				ModalDisplayName: "Username",
				CLIName:          "username",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Target username (DOMAIN\\user or user@domain)",
				DefaultValue:     "",
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
				Description:      "Target user's password. Required on Windows. On Linux/macOS: required if not root (uses sudo -S); optional if root (uses setuid).",
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "domain",
				ModalDisplayName: "Domain",
				CLIName:          "domain",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Domain (optional, can be part of username)",
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "netonly",
				ModalDisplayName: "Network Only",
				CLIName:          "netonly",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_BOOLEAN,
				Description:      "Use LOGON_NETCREDENTIALS_ONLY (like runas /netonly — local access as current user, network access as specified user)",
				DefaultValue:     false,
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
			username, _ := taskData.Args.GetStringArg("username")
			return agentstructs.PTTTaskOPSECPreTaskMessageResponse{
				TaskID: taskData.Task.ID, Success: true,
				OpsecPreBlocked:    false,
				OpsecPreMessage:    fmt.Sprintf("OPSEC WARNING: Executing command as user '%s' (T1134.002). Process creation under alternate credentials generates Windows Security Event 4648 (explicit credential logon) and EDR process-tree anomalies.", username),
				OpsecPreBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionOPSECPost: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskOPSECPostTaskMessageResponse {
			return agentstructs.PTTaskOPSECPostTaskMessageResponse{
				TaskID:              taskData.Task.ID,
				Success:             true,
				OpsecPostBlocked:    false,
				OpsecPostMessage:    "OPSEC AUDIT: Process spawned with alternate credentials. Generates Event ID 4624 (logon type 2/9) and Event ID 4688 (process creation). The spawned process inherits the new token context. Use 'rev2self' if operating under the spawned context.",
				OpsecPostBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
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
			username, _ := taskData.Args.GetStringArg("username")
			domain, _ := taskData.Args.GetStringArg("domain")
			display := username
			if domain != "" {
				display = fmt.Sprintf("%s\\%s", domain, username)
			}
			response.DisplayParams = &display
			user := username
			if domain != "" {
				user = fmt.Sprintf("%s\\%s", domain, username)
			}
			createArtifact(taskData.Task.ID, "Process Create", fmt.Sprintf("Process execution as %s", user))
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
			username, _ := processResponse.TaskData.Args.GetStringArg("username")
			if !strings.Contains(strings.ToLower(responseText), "error") && !strings.Contains(strings.ToLower(responseText), "failed") {
				createArtifact(processResponse.TaskData.Task.ID, "Remote Command",
					fmt.Sprintf("[RunAs] Executed as %s", username))
			}
			return response
		},
	})
}
