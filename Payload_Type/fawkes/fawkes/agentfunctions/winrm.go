package agentfunctions

import (
	"fmt"
	"path/filepath"
	"regexp"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "winrm",
		Description:         "Execute commands on remote Windows hosts via WinRM with NTLM authentication. Supports cmd.exe and PowerShell shells. Supports pass-the-hash.",
		HelpString:          "winrm -host 192.168.1.1 -username admin -password pass -command \"whoami\"\nwinrm -host 192.168.1.1 -username DOMAIN\\admin -password pass -command \"Get-Process\" -shell powershell\nwinrm -host 192.168.1.1 -username admin -hash aad3b435b51404ee:8846f7eaee8fb117 -command \"whoami\" -domain DOMAIN\nwinrm -host 192.168.1.1 -username admin -password pass -command \"ipconfig /all\" -port 5986 -use_tls true",
		Version:             1,
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1021.006", "T1550.002"},
		AssociatedBrowserScript: &agentstructs.BrowserScript{ScriptPath: filepath.Join(".", "fawkes", "browserscripts", "winrm_new.js"), Author: "@galoryber"},
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{
				agentstructs.SUPPORTED_OS_WINDOWS,
				agentstructs.SUPPORTED_OS_LINUX,
				agentstructs.SUPPORTED_OS_MACOS,
			},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:                 "host",
				CLIName:              "host",
				ModalDisplayName:     "Target Host",
				Description:          "Remote host IP or hostname",
				ParameterType:        agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:         "",
				DynamicQueryFunction: getActiveHostList,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: true, GroupName: "Default"},
				},
			},
			{
				Name:                 "username",
				CLIName:              "username",
				ModalDisplayName:     "Username",
				Description:          "Username for NTLM auth (supports DOMAIN\\user format)",
				DynamicQueryFunction: getCallbackUserList,
				ParameterType:        agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:         "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: true, GroupName: "Default"},
				},
			},
			{
				Name:             "password",
				CLIName:          "password",
				ModalDisplayName: "Password",
				Description:      "Password for NTLM auth (or use -hash for pass-the-hash)",
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
				Description:      "NT hash for pass-the-hash (hex, e.g., aad3b435b51404ee:8846f7eaee8fb117 or just the NT hash)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "command",
				CLIName:          "command",
				ModalDisplayName: "Command",
				Description:      "Command to execute on the remote host",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: true, GroupName: "Default"},
				},
			},
			{
				Name:             "shell",
				CLIName:          "shell",
				ModalDisplayName: "Shell",
				Description:      "Shell to use: cmd (default) or powershell",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:          []string{"cmd", "powershell"},
				DefaultValue:     "cmd",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "port",
				CLIName:          "port",
				ModalDisplayName: "WinRM Port",
				Description:      "WinRM port (default: 5985 for HTTP, 5986 for HTTPS)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				DefaultValue:     5985,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "use_tls",
				CLIName:          "use_tls",
				ModalDisplayName: "Use TLS (HTTPS)",
				Description:      "Use HTTPS/TLS for WinRM connection (port 5986)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_BOOLEAN,
				DefaultValue:     false,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "timeout",
				CLIName:          "timeout",
				ModalDisplayName: "Timeout (seconds)",
				Description:      "Command execution timeout in seconds (default: 60)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				DefaultValue:     60,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
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
			host, _ := taskData.Args.GetStringArg("host")
			return agentstructs.PTTTaskOPSECPreTaskMessageResponse{
				TaskID:             taskData.Task.ID,
				Success:            true,
				OpsecPreBlocked:    false,
				OpsecPreMessage:    fmt.Sprintf("OPSEC WARNING: WinRM remote command execution on %s. Creates network logon (Event ID 4624 type 3) and WinRM operational logs (Event ID 91, 161). WinRM lateral movement is a high-fidelity detection indicator.", host),
				OpsecPreBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionOPSECPost: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskOPSECPostTaskMessageResponse {
			return agentstructs.PTTaskOPSECPostTaskMessageResponse{
				TaskID:              taskData.Task.ID,
				Success:             true,
				OpsecPostBlocked:    false,
				OpsecPostMessage:    "OPSEC AUDIT: WinRM execution completed. Generates Event ID 4624 (logon type 3) and Event ID 91/168 in Microsoft-Windows-WinRM/Operational on the target. WSMan connections may be visible to PowerShell script block logging.",
				OpsecPostBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
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
			// Parse: [*] WinRM user@host:port (shell, auth)
			re := regexp.MustCompile(`\[\*\]\s+WinRM\s+(\S+)@(\S+?):(\d+)\s+\((\S+),`)
			if m := re.FindStringSubmatch(responseText); len(m) > 3 {
				createArtifact(processResponse.TaskData.Task.ID, "Remote Command",
					fmt.Sprintf("WinRM execution: %s@%s:%s (%s)", m[1], m[2], m[3], m[4]))
				tagTask(processResponse.TaskData.Task.ID, "LATERAL",
					fmt.Sprintf("WinRM execution on %s as %s", m[2], m[1]))
			}
			return response
		},
		TaskFunctionCreateTasking: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  taskData.Task.ID,
			}

			host, _ := taskData.Args.GetStringArg("host")
			command, _ := taskData.Args.GetStringArg("command")
			shell, _ := taskData.Args.GetStringArg("shell")

			displayMsg := fmt.Sprintf("WinRM %s %s@%s: %s", shell, "", host, command)
			response.DisplayParams = &displayMsg

			createArtifact(taskData.Task.ID, "Network Connection", fmt.Sprintf("WinRM connection to %s (%s: %s)", host, shell, command))
			logOperationEvent(taskData.Task.ID,
				fmt.Sprintf("[LATERAL] winrm: remote execution on %s from %s", host, taskData.Callback.Host), true)

			return response
		},
	})
}
