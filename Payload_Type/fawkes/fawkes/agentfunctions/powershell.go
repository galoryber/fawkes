package agentfunctions

import (
	"fmt"
	"path/filepath"
	"strings"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "powershell",
		Description:         "Execute a PowerShell command or script with OPSEC-hardened invocation flags",
		HelpString:          "powershell <command> or powershell {\"command\": \"...\", \"encoded\": true}",
		Version:             2,
		MitreAttackMappings: []string{"T1059.001"}, // Command and Scripting Interpreter: PowerShell
		SupportedUIFeatures: []string{},
		Author:              "@galoryber",
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_WINDOWS},
			FilterCommandAvailabilityByAgentBuildParameters: map[string]string{"selected_os": "Windows"},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:             "command",
				CLIName:          "command",
				ModalDisplayName: "Command",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "The PowerShell command or script to execute",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: true, GroupName: "Default", UIModalPosition: 1},
				},
			},
			{
				Name:             "encoded",
				CLIName:          "encoded",
				ModalDisplayName: "Encoded Command",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_BOOLEAN,
				Description:      "Use -EncodedCommand (base64 UTF-16LE) to hide the command from process tree listings",
				DefaultValue:     false,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default", UIModalPosition: 2},
				},
			},
		},
		AssociatedBrowserScript: &agentstructs.BrowserScript{ScriptPath: filepath.Join(".", "fawkes", "browserscripts", "powershell_new.js"), Author: "@galoryber"},
		TaskFunctionParseArgString: func(args *agentstructs.PTTaskMessageArgsData, input string) error {
			if input == "" {
				return nil
			}
			// Try JSON first (from UI modal or structured input)
			if err := args.LoadArgsFromJSONString(input); err == nil {
				return nil
			}
			// Not JSON — treat entire input as the command (backward compat + CLI usage)
			return args.SetArgValue("command", input)
		},
		TaskFunctionParseArgDictionary: func(args *agentstructs.PTTaskMessageArgsData, input map[string]interface{}) error {
			return args.LoadArgsFromDictionary(input)
		},
		TaskFunctionOPSECPre: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTTaskOPSECPreTaskMessageResponse {
			cmd, _ := taskData.Args.GetStringArg("command")
			msg := "OPSEC WARNING: PowerShell execution"
			if cmd != "" {
				msg = fmt.Sprintf("OPSEC WARNING: PowerShell execution of command. PowerShell ScriptBlock Logging (Event ID 4104), Module Logging, and Transcription may capture the full command text. AMSI will inspect the script before execution. Consider using execute-assembly or inline-execute for stealthier alternatives.")
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
				OpsecPostMessage:    "OPSEC AUDIT: PowerShell execution completed. Commands logged in Event ID 4103/4104 (ScriptBlock Logging). AMSI scans content in memory. Consider direct API calls for stealth.",
				OpsecPostBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionCreateTasking: func(task *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  task.Task.ID,
			}
			cmd, _ := task.Args.GetStringArg("command")
			encoded, _ := task.Args.GetBooleanArg("encoded")
			if cmd != "" {
				dp := cmd
				if encoded {
					dp = "[encoded] " + cmd
				}
				response.DisplayParams = &dp
				// Artifact shows abbreviated flag form (actual flags are randomized at runtime)
				if encoded {
					createArtifact(task.Task.ID, "Process Create", "powershell.exe -nop -ep bypass -enc <base64>")
				} else {
					createArtifact(task.Task.ID, "Process Create", "powershell.exe -nop -ep bypass -Command "+cmd)
				}
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
			if strings.Contains(responseText, "output") || strings.Contains(responseText, "Output") || len(responseText) > 0 {
				cmd, _ := processResponse.TaskData.Args.GetStringArg("command")
				l := len(cmd)
				if l > 200 {
					l = 200
				}
				createArtifact(processResponse.TaskData.Task.ID, "Command Execution", fmt.Sprintf("[powershell] %s", cmd[:l]))
			}
			return response
		},
	})
}
