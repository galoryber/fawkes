package agentfunctions

import (
	"fmt"
	"path/filepath"
	"strings"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func formatRemoteRegOPSEC(action, server string) string {
	msg := fmt.Sprintf("OPSEC WARNING: Remote registry %s via RPC named pipe (winreg) on %s.", action, server)
	if action == "set" || action == "delete" {
		msg += " Write/delete operations modify the remote registry — may trigger EDR alerts for remote registry modification."
	}
	msg += " Uses SMB named pipe transport (ncacn_np:[winreg]) — generates network logon and SMB events."
	return msg
}

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "remote-reg",
		Description:         "Read/write registry keys on remote Windows hosts via WinReg RPC (port 135). Supports pass-the-hash. Useful for reading LAPS passwords, checking security configs, and planting persistence on remote hosts without executing code.",
		HelpString:          "remote-reg -action enum -server 192.168.1.1 -hive HKLM -path SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run -username DOMAIN\\admin -password pass\nremote-reg -action query -server dc01 -path SOFTWARE\\Policies\\Microsoft Services\\AdmPwd -name AdmPwdEnabled -username admin -hash aad3b435b51404ee:8846f7eaee8fb117 -domain CORP.LOCAL\nremote-reg -action set -server 192.168.1.1 -hive HKCU -path SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run -name Updater -data C:\\payload.exe -reg_type REG_SZ -username admin -password pass",
		Version:             1,
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1012", "T1112", "T1021.002"},
		AssociatedBrowserScript: &agentstructs.BrowserScript{
			ScriptPath: filepath.Join(".", "fawkes", "browserscripts", "remote_reg_new.js"),
			Author:     "@galoryber",
		},
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
				Description:      "Operation to perform: query (read value), enum (list subkeys/values), set (write value), delete (remove key/value)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:          []string{"query", "enum", "set", "delete"},
				DefaultValue:     "enum",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: true, GroupName: "Default"},
				},
			},
			{
				Name:                "server",
				CLIName:             "server",
				ModalDisplayName:    "Target Server",
				Description:         "Remote Windows host IP or hostname",
				ParameterType:       agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:        "",
				DynamicQueryFunction: getActiveHostList,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: true, GroupName: "Default"},
				},
			},
			{
				Name:             "hive",
				CLIName:          "hive",
				ModalDisplayName: "Registry Hive",
				Description:      "Registry hive to open",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:          []string{"HKLM", "HKCU", "HKU", "HKCR"},
				DefaultValue:     "HKLM",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "path",
				CLIName:          "path",
				ModalDisplayName: "Key Path",
				Description:      "Registry key path (e.g., SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "name",
				CLIName:          "name",
				ModalDisplayName: "Value Name",
				Description:      "Registry value name (for query, set, or delete value)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "data",
				CLIName:          "data",
				ModalDisplayName: "Value Data",
				Description:      "Data to write (for set action)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "reg_type",
				CLIName:          "reg_type",
				ModalDisplayName: "Value Type",
				Description:      "Registry value type (for set action)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:          []string{"REG_SZ", "REG_EXPAND_SZ", "REG_DWORD", "REG_QWORD", "REG_BINARY"},
				DefaultValue:     "REG_SZ",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "username",
				CLIName:          "username",
				ModalDisplayName: "Username",
				Description:      "Account for authentication (DOMAIN\\user or user@domain)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:     "",
				DynamicQueryFunction: getCallbackUserList,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: true, GroupName: "Default"},
				},
			},
			{
				Name:             "password",
				CLIName:          "password",
				ModalDisplayName: "Password",
				Description:      "Password for authentication (or use -hash)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "hash",
				CLIName:          "hash",
				ModalDisplayName: "NTLM Hash",
				Description:      "NT hash for pass-the-hash (LM:NT or just NT part)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "domain",
				CLIName:          "domain",
				ModalDisplayName: "Domain",
				Description:      "Domain name (auto-detected from username if DOMAIN\\user format)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:     "",
				DynamicQueryFunction: getCallbackDomainList,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "timeout",
				CLIName:          "timeout",
				ModalDisplayName: "Timeout (seconds)",
				Description:      "Connection timeout in seconds (default: 30)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				DefaultValue:     30,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
		},
		TaskFunctionOPSECPre: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTTaskOPSECPreTaskMessageResponse {
			action, _ := taskData.Args.GetStringArg("action")
			server, _ := taskData.Args.GetStringArg("server")
			msg := formatRemoteRegOPSEC(action, server)
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
				OpsecPostMessage:    "OPSEC AUDIT: Remote registry operation completed. Remote registry access generates Event ID 4663 on target. winreg pipe connections are logged. Security key reads are high-priority detections.",
				OpsecPostBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionCreateTasking: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  taskData.Task.ID,
			}
			action, _ := taskData.Args.GetStringArg("action")
			server, _ := taskData.Args.GetStringArg("server")
			hive, _ := taskData.Args.GetStringArg("hive")
			path, _ := taskData.Args.GetStringArg("path")
			artifactMsg := fmt.Sprintf("WinReg RPC %s on %s: %s\\%s", action, server, hive, path)
			createArtifact(taskData.Task.ID, "Network Connection", artifactMsg)
			display := fmt.Sprintf("%s %s %s\\%s", action, server, hive, path)
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
			server, _ := processResponse.TaskData.Args.GetStringArg("server")
			switch action {
			case "write", "delete":
				if strings.Contains(responseText, "success") || strings.Contains(responseText, "Success") {
					logOperationEvent(processResponse.TaskData.Task.ID,
						fmt.Sprintf("[LATERAL] Remote registry %s on %s (T1112)", action, server), true)
				}
			case "read", "query":
				logOperationEvent(processResponse.TaskData.Task.ID,
					fmt.Sprintf("[DISCOVERY] Remote registry %s on %s (T1012)", action, server), false)
			}
			return response
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
	})
}
