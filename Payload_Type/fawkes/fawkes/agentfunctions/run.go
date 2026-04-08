package agentfunctions

import (
	"encoding/json"
	"fmt"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "run",
		Description:         "run [command] - Execute a command in a child process",
		HelpString:          "run [command]",
		Version:             1,
		MitreAttackMappings: []string{"T1059"}, // Command and Scripting Interpreter
		SupportedUIFeatures: []string{},
		Author:              "@galoryber",
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS:        []string{agentstructs.SUPPORTED_OS_LINUX, agentstructs.SUPPORTED_OS_MACOS, agentstructs.SUPPORTED_OS_WINDOWS},
			CommandIsSuggested: true,
		},
		TaskFunctionParseArgString: func(args *agentstructs.PTTaskMessageArgsData, input string) error {
			// Try to parse as JSON first (API-submitted params like {"command": "hostname"})
			var parsed map[string]interface{}
			if err := json.Unmarshal([]byte(input), &parsed); err == nil {
				if cmd, ok := parsed["command"].(string); ok {
					args.SetManualArgs(cmd)
					return nil
				}
			}
			// Fall back to raw string (CLI usage: run hostname)
			args.SetManualArgs(input)
			return nil
		},
		TaskFunctionParseArgDictionary: func(args *agentstructs.PTTaskMessageArgsData, input map[string]interface{}) error {
			// If called from dictionary (unlikely for this command), just convert to string
			if cmd, ok := input["command"].(string); ok {
				args.SetManualArgs(cmd)
			}
			return nil
		},
		TaskFunctionOPSECPre: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTTaskOPSECPreTaskMessageResponse {
			return agentstructs.PTTTaskOPSECPreTaskMessageResponse{
				TaskID: taskData.Task.ID, Success: true,
				OpsecPreBlocked: false,
				OpsecPreMessage:    "OPSEC WARNING: Executing system command (T1059). Process creation is logged by EDR (Sysmon Event ID 1). Command-line arguments are recorded and subject to behavioral analysis.",
				OpsecPreBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionCreateTasking: func(task *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  task.Task.ID,
			}
			// Display the command being executed
			if displayParams, err := task.Args.GetFinalArgs(); err == nil {
				response.DisplayParams = &displayParams
				createArtifact(task.Task.ID, "Process Create", displayParams)
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
			cmd, _ := processResponse.TaskData.Args.GetStringArg("command")
			if cmd == "" {
				cmd, _ = processResponse.TaskData.Args.GetFinalArgs()
			}
			createArtifact(processResponse.TaskData.Task.ID, "Process Create",
				fmt.Sprintf("run: %s (%d bytes output)", cmd, len(responseText)))
			return response
		},
	})
}
