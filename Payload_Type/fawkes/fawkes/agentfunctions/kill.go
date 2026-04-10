package agentfunctions

import (
	"fmt"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
	"github.com/MythicMeta/MythicContainer/logging"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "kill",
		Description:         "Terminate a process by PID.",
		HelpString:          "kill -pid 1234",
		Version:             1,
		MitreAttackMappings: []string{"T1489"}, // Service Stop (closest mapping)
		SupportedUIFeatures: []string{"process_browser:kill"},
		Author:              "@galoryber",
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_WINDOWS, agentstructs.SUPPORTED_OS_LINUX, agentstructs.SUPPORTED_OS_MACOS},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:             "pid",
				ModalDisplayName: "Process ID",
				CLIName:          "pid",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "PID of the process to terminate",
				DynamicQueryFunction: getProcessList,
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: true,
						GroupName:           "Default",
						UIModalPosition:     0,
					},
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
			pidVal, _ := taskData.Args.GetStringArg("pid")
			msg := fmt.Sprintf("OPSEC WARNING: Killing process PID %s (T1489, T1562). Process termination is logged by EDR. Killing security processes (AV, EDR, SIEM agents) triggers high-confidence alerts and may cause automated incident response.", pidVal)
			return agentstructs.PTTTaskOPSECPreTaskMessageResponse{
				TaskID: taskData.Task.ID, Success: true,
				OpsecPreBlocked: false, OpsecPreMessage: msg,
				OpsecPreBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionOPSECPost: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskOPSECPostTaskMessageResponse {
			return agentstructs.PTTaskOPSECPostTaskMessageResponse{
				TaskID:              taskData.Task.ID,
				Success:             true,
				OpsecPostBlocked:    false,
				OpsecPostMessage:    "OPSEC AUDIT: Process terminated. Process termination logged in Event ID 4689 (process exit). Killing security products triggers immediate alerts. Consider the impact before terminating processes.",
				OpsecPostBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionCreateTasking: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  taskData.Task.ID,
			}

			pid, err := parsePIDFromArg(taskData)
			if err != nil {
				logging.LogError(err, "Failed to get pid")
				response.Success = false
				response.Error = "Failed to get PID: " + err.Error()
				return response
			}

			if pid <= 0 {
				response.Success = false
				response.Error = "PID must be greater than 0"
				return response
			}

			displayParams := fmt.Sprintf("PID: %d", pid)
			response.DisplayParams = &displayParams
			createArtifact(taskData.Task.ID, "Process Kill", fmt.Sprintf("Killed PID %d", pid))

			return response
		},
	})
}
