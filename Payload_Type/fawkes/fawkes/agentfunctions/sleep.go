package agentfunctions

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/MythicMeta/MythicContainer/logging"
	"github.com/MythicMeta/MythicContainer/mythicrpc"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "sleep",
		Description:         "Update the sleep interval, jitter, and working hours of the agent.",
		HelpString:          "sleep {interval} [jitter%] [working_start] [working_end] [working_days]",
		Version:             1,
		Author:              "@galoryber",
		MitreAttackMappings: []string{},
		SupportedUIFeatures: []string{},
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_LINUX, agentstructs.SUPPORTED_OS_MACOS, agentstructs.SUPPORTED_OS_WINDOWS},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:             "interval",
				ModalDisplayName: "Interval Seconds",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				DefaultValue:     0,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: true,
						UIModalPosition:     1,
					},
				},
				Description: "Sleep time in seconds",
			},
			{
				Name:             "jitter",
				ModalDisplayName: "Jitter Percentage",
				DefaultValue:     0,
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     2,
					},
				},
				Description: "Percentage of jitter on the interval",
			},
			{
				Name:             "working_start",
				ModalDisplayName: "Working Hours Start",
				DefaultValue:     "",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     3,
					},
				},
				Description: "Working hours start time in HH:MM 24-hour format (e.g. 09:00). Agent sleeps outside working hours. Leave empty for no change, set both to 00:00 to disable.",
			},
			{
				Name:             "working_end",
				ModalDisplayName: "Working Hours End",
				DefaultValue:     "",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     4,
					},
				},
				Description: "Working hours end time in HH:MM 24-hour format (e.g. 17:00).",
			},
			{
				Name:             "working_days",
				ModalDisplayName: "Working Days",
				DefaultValue:     "",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     5,
					},
				},
				Description: "Comma-separated ISO weekday numbers (Mon=1, Sun=7). E.g. '1,2,3,4,5' for weekdays. Leave empty for no change, '0' to disable (all days).",
			},
		},
		TaskFunctionCreateTasking: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  taskData.Task.ID,
			}
			interval, _ := taskData.Args.GetNumberArg("interval")
			jitter, _ := taskData.Args.GetNumberArg("jitter")
			display := fmt.Sprintf("%ds", int(interval))
			if jitter > 0 {
				display += fmt.Sprintf(" %d%%", int(jitter))
			}
			response.DisplayParams = &display
			return response
		},
		TaskFunctionProcessResponse: func(processResponse agentstructs.PtTaskProcessResponseMessage) agentstructs.PTTaskProcessResponseMessageResponse {
			response := agentstructs.PTTaskProcessResponseMessageResponse{
				TaskID:  processResponse.TaskData.Task.ID,
				Success: true,
			}
			sleepString := processResponse.Response.(string)
			if updateResp, err := mythicrpc.SendMythicRPCCallbackUpdate(mythicrpc.MythicRPCCallbackUpdateMessage{
				AgentCallbackUUID: &processResponse.TaskData.Callback.AgentCallbackID,
				SleepInfo:         &sleepString,
			}); err != nil {
				response.Success = false
				response.Error = err.Error()
			} else if !updateResp.Success {
				response.Success = false
				response.Error = updateResp.Error
			}
			return response
		},
		TaskFunctionParseArgDictionary: func(args *agentstructs.PTTaskMessageArgsData, input map[string]interface{}) error {
			return args.LoadArgsFromDictionary(input)
		},
		TaskFunctionParseArgString: func(args *agentstructs.PTTaskMessageArgsData, input string) error {
			// Try JSON first (e.g., {"interval": 2, "jitter": 10} from API)
			if err := args.LoadArgsFromJSONString(input); err == nil {
				return nil
			}
			stringPieces := strings.Split(input, " ")
			if len(stringPieces) < 1 || len(stringPieces) > 5 {
				return errors.New("Expected 1-5 arguments: interval [jitter] [working_start] [working_end] [working_days]")
			}
			// Parse interval (required)
			if interval, err := strconv.Atoi(stringPieces[0]); err != nil {
				logging.LogError(err, "Failed to process first argument as integer")
				return err
			} else if interval < 0 {
				args.SetArgValue("interval", 0)
			} else {
				args.SetArgValue("interval", interval)
			}
			// Parse jitter (optional)
			if len(stringPieces) >= 2 {
				if jitter, err := strconv.Atoi(stringPieces[1]); err != nil {
					return err
				} else {
					if jitter < 0 {
						args.SetArgValue("jitter", 0)
					} else {
						args.SetArgValue("jitter", jitter)
					}
				}
			}
			// Parse working hours (optional)
			if len(stringPieces) >= 3 {
				args.SetArgValue("working_start", stringPieces[2])
			}
			if len(stringPieces) >= 4 {
				args.SetArgValue("working_end", stringPieces[3])
			}
			if len(stringPieces) >= 5 {
				args.SetArgValue("working_days", stringPieces[4])
			}
			return nil
		},
	})
}
