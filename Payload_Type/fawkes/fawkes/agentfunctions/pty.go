package agentfunctions

import (
	"encoding/json"
	"path/filepath"
	"strings"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "pty",
		Description:         "Start an interactive PTY shell session (Linux/macOS only)",
		HelpString:          "pty",
		Version:             1,
		MitreAttackMappings: []string{"T1059", "T1059.004"}, // Command and Scripting Interpreter (Unix Shell)
		SupportedUIFeatures: []string{"task_response:interactive"},
		Author:              "@galoryber",
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_LINUX, agentstructs.SUPPORTED_OS_MACOS},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:          "shell",
				CLIName:       "shell",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:   "Shell binary path (default: auto-detect from $SHELL or /bin/bash)",
				DefaultValue:  "",

				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:          "rows",
				CLIName:       "rows",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				Description:   "Initial terminal rows (default: 24)",
				DefaultValue:  24,

				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:          "cols",
				CLIName:       "cols",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				Description:   "Initial terminal columns (default: 80)",
				DefaultValue:  80,

				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
		},
		AssociatedBrowserScript: &agentstructs.BrowserScript{ScriptPath: filepath.Join(".", "fawkes", "browserscripts", "pty_new.js"), Author: "@galoryber"},
		TaskFunctionParseArgString: func(args *agentstructs.PTTaskMessageArgsData, input string) error {
			// Try JSON first (API-submitted params like {"shell": "/bin/zsh"})
			if input != "" {
				var parsed map[string]interface{}
				if err := json.Unmarshal([]byte(input), &parsed); err == nil {
					return args.LoadArgsFromDictionary(parsed)
				}
				// Raw string that looks like a path → use as shell
				if strings.HasPrefix(input, "/") {
					args.SetArgValue("shell", input)
				}
			}
			return nil
		},
		TaskFunctionParseArgDictionary: func(args *agentstructs.PTTaskMessageArgsData, input map[string]interface{}) error {
			return args.LoadArgsFromDictionary(input)
		},
		TaskFunctionOPSECPre: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTTaskOPSECPreTaskMessageResponse {
			return agentstructs.PTTTaskOPSECPreTaskMessageResponse{
				TaskID:             taskData.Task.ID,
				Success:            true,
				OpsecPreBlocked:    false,
				OpsecPreMessage:    "OPSEC WARNING: PTY allocation spawns a new shell process (cmd.exe/powershell/bash). Shell process creation is a high-fidelity EDR detection signal. Interactive sessions generate ongoing process and command-line telemetry.",
				OpsecPreBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionOPSECPost: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskOPSECPostTaskMessageResponse {
			return agentstructs.PTTaskOPSECPostTaskMessageResponse{
				TaskID:              taskData.Task.ID,
				Success:             true,
				OpsecPostBlocked:    false,
				OpsecPostMessage:    "OPSEC AUDIT: PTY session active. Interactive terminal sessions generate process creation events. Shell commands are logged by auditd/sysmon. Session cleanup recommended after use.",
				OpsecPostBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionCreateTasking: func(task *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  task.Task.ID,
			}
			displayParams := "interactive PTY shell"
			if shell, err := task.Args.GetStringArg("shell"); err == nil && shell != "" {
				displayParams = "PTY: " + shell
			}
			response.DisplayParams = &displayParams
			return response
		},
	})
}
