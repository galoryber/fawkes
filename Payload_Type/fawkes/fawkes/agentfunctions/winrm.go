package agentfunctions

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
	"github.com/MythicMeta/MythicContainer/mythicrpc"
)

var winrmExecutionRegex = regexp.MustCompile(`\[\*\]\s+WinRM\s+(\S+)@(\S+?):(\d+)\s+\((\S+),`)

func extractWinRMExecutionInfo(responseText string) (user, host, port, shell string, ok bool) {
	m := winrmExecutionRegex.FindStringSubmatch(responseText)
	if len(m) > 4 {
		return m[1], m[2], m[3], m[4], true
	}
	return "", "", "", "", false
}

func countPrivilegeLines(text string) int {
	return strings.Count(text, "\n")
}

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "winrm",
		Description:         "Execute commands on remote Windows hosts via WinRM with NTLM authentication. Supports cmd.exe and PowerShell shells. Supports pass-the-hash.",
		HelpString:          "winrm -host <target> -username <user> -password <pass> -command <cmd> OR winrm -action check -host <target> [-username <user> -password <pass>]",
		Version:             2,
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
		TaskCompletionFunctions: map[string]agentstructs.PTTaskCompletionFunction{
			"winrmAutoVerifyWhoamiDone":   winrmAutoVerifyWhoamiDone,
			"winrmAutoVerifyGetprivsDone": winrmAutoVerifyGetprivsDone,
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:             "action",
				CLIName:          "action",
				ModalDisplayName: "Action",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:          []string{"execute", "check"},
				Description:      "execute: run command on remote host. check: validate WinRM prerequisites.",
				DefaultValue:     "execute",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
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
			{
				Name:             "auto_verify",
				CLIName:          "auto-verify",
				ModalDisplayName: "Auto-Verify (whoami + getprivs)",
				Description:      "After WinRM execution, automatically run whoami and getprivs locally to verify callback context",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_BOOLEAN,
				DefaultValue:     false,
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
			msg := fmt.Sprintf("OPSEC WARNING: WinRM remote command execution on %s. Creates network logon (Event ID 4624 type 3) and WinRM operational logs (Event ID 91, 161). WinRM lateral movement is a high-fidelity detection indicator.", host)
			if ctx := identityContextForOPSEC(taskData.Callback.Description); ctx != "" {
				msg += " [Identity: " + ctx + "]"
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
			if user, host, port, shell, ok := extractWinRMExecutionInfo(responseText); ok {
				createArtifact(processResponse.TaskData.Task.ID, "Remote Command",
					fmt.Sprintf("WinRM execution: %s@%s:%s (%s)", user, host, port, shell))
				tagTask(processResponse.TaskData.Task.ID, "LATERAL",
					fmt.Sprintf("WinRM execution on %s as %s", host, user))
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
			autoVerify, _ := taskData.Args.GetBooleanArg("auto_verify")

			displayMsg := fmt.Sprintf("WinRM %s %s@%s: %s", shell, "", host, command)
			if autoVerify {
				displayMsg += " [auto-verify: whoami \u2192 getprivs]"

				// Create whoami subtask → chains to getprivs on completion
				callbackFunc := "winrmAutoVerifyWhoamiDone"
				if _, err := mythicrpc.SendMythicRPCTaskCreateSubtask(mythicrpc.MythicRPCTaskCreateSubtaskMessage{
					TaskID: taskData.Task.ID, SubtaskCallbackFunction: &callbackFunc,
					CommandName: "whoami", Params: `{}`,
				}); err != nil {
					response.Success = false
					response.Error = fmt.Sprintf("Failed to create auto-verify whoami: %v", err)
					return response
				}
				createArtifact(taskData.Task.ID, "Subtask Chain",
					fmt.Sprintf("WinRM auto-verify: %s → whoami → getprivs", host))
			}
			response.DisplayParams = &displayMsg

			createArtifact(taskData.Task.ID, "Network Connection", fmt.Sprintf("WinRM connection to %s (%s: %s)", host, shell, command))
			logOperationEvent(taskData.Task.ID,
				fmt.Sprintf("[LATERAL] winrm: remote execution on %s from %s", host, taskData.Callback.Host), true)

			return response
		},
	})
}

// --- WinRM auto-verify subtask chain ---

// winrmAutoVerifyWhoamiDone handles whoami completion → chains to getprivs.
func winrmAutoVerifyWhoamiDone(
	taskData *agentstructs.PTTaskMessageAllData,
	subtaskData *agentstructs.PTTaskMessageAllData,
	_ *agentstructs.SubtaskGroupName,
) agentstructs.PTTaskCompletionFunctionMessageResponse {
	response := agentstructs.PTTaskCompletionFunctionMessageResponse{
		TaskID:  taskData.Task.ID,
		Success: true,
	}

	responseText := getSubtaskResponses(subtaskData.Task.ID)
	mythicrpc.SendMythicRPCResponseCreate(mythicrpc.MythicRPCResponseCreateMessage{
		TaskID:   taskData.Task.ID,
		Response: []byte(fmt.Sprintf("[auto-verify] Identity: %s", strings.TrimSpace(responseText))),
	})

	callbackFunc := "winrmAutoVerifyGetprivsDone"
	if _, err := mythicrpc.SendMythicRPCTaskCreateSubtask(mythicrpc.MythicRPCTaskCreateSubtaskMessage{
		TaskID: taskData.Task.ID, SubtaskCallbackFunction: &callbackFunc,
		CommandName: "getprivs", Params: `{}`,
	}); err != nil {
		completed := true
		response.Completed = &completed
		msg := fmt.Sprintf("auto-verify: whoami OK but getprivs failed: %s", err.Error())
		response.Stderr = &msg
	}
	return response
}

// winrmAutoVerifyGetprivsDone handles getprivs completion → aggregates results.
func winrmAutoVerifyGetprivsDone(
	taskData *agentstructs.PTTaskMessageAllData,
	subtaskData *agentstructs.PTTaskMessageAllData,
	_ *agentstructs.SubtaskGroupName,
) agentstructs.PTTaskCompletionFunctionMessageResponse {
	response := agentstructs.PTTaskCompletionFunctionMessageResponse{
		TaskID:  taskData.Task.ID,
		Success: true,
	}

	responseText := getSubtaskResponses(subtaskData.Task.ID)
	privCount := countPrivilegeLines(responseText)

	mythicrpc.SendMythicRPCResponseCreate(mythicrpc.MythicRPCResponseCreateMessage{
		TaskID:   taskData.Task.ID,
		Response: []byte(fmt.Sprintf("[auto-verify] Privileges: %d available. Callback context verified.", privCount)),
	})

	return response
}
