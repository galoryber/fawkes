package agentfunctions

import (
	"encoding/json"
	"fmt"
	"path/filepath"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
	"github.com/MythicMeta/MythicContainer/logging"
	"github.com/MythicMeta/MythicContainer/mythicrpc"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "ps",
		Description:         "List running processes with optional filtering by name, PID, parent PID, or username.",
		HelpString:          "ps [-filter <name>] [-pid <PID>] [-ppid <parent_PID>] [-user <username>] [-v]",
		Version:             2,
		MitreAttackMappings: []string{"T1057"},
		SupportedUIFeatures: []string{"process_browser:list"},
		Author:              "@galoryber",
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS:        []string{agentstructs.SUPPORTED_OS_LINUX, agentstructs.SUPPORTED_OS_MACOS, agentstructs.SUPPORTED_OS_WINDOWS},
			CommandIsSuggested: true,
		},
		AssociatedBrowserScript: &agentstructs.BrowserScript{
			ScriptPath: filepath.Join(".", "fawkes", "browserscripts", "ps_new.js"),
			Author:     "@galoryber",
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:          "filter",
				CLIName:       "filter",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:  "",
				Description:   "Filter by process name (case-insensitive substring match)",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     1,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:                 "pid",
				CLIName:              "pid",
				ParameterType:        agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:         "",
				Description:          "Filter by specific process ID",
				DynamicQueryFunction: getProcessList,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     2,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:          "ppid",
				CLIName:       "ppid",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				DefaultValue:  0,
				Description:   "Filter by parent process ID (find child processes)",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     3,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:                 "user",
				CLIName:              "user",
				ParameterType:        agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:         "",
				Description:          "Filter by username (case-insensitive substring match)",
				DynamicQueryFunction: getCallbackUserList,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     4,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:          "verbose",
				CLIName:       "v",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_BOOLEAN,
				DefaultValue:  false,
				Description:   "Include command line in output",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     5,
						GroupName:           "Default",
					},
				},
			},
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
			// Parse the full process list from agent response
			var processes []struct {
				ProcessID       int    `json:"process_id"`
				ParentProcessID int    `json:"parent_process_id"`
				Name            string `json:"name"`
				Architecture    string `json:"architecture"`
				User            string `json:"user"`
				BinPath         string `json:"bin_path"`
				CommandLine     string `json:"command_line"`
				IntegrityLevel  int    `json:"integrity_level"`
				StartTime       int64  `json:"start_time"`
			}
			if err := json.Unmarshal([]byte(responseText), &processes); err != nil {
				return response
			}

			// Populate Mythic process browser via RPC with host enrichment
			if len(processes) > 0 {
				host := processResponse.TaskData.Callback.Host
				rpcProcesses := make([]mythicrpc.MythicRPCProcessCreateProcessData, len(processes))
				for i, p := range processes {
					rpcProcesses[i] = mythicrpc.MythicRPCProcessCreateProcessData{
						Host:            &host,
						ProcessID:       p.ProcessID,
						ParentProcessID: p.ParentProcessID,
						Name:            p.Name,
						Architecture:    p.Architecture,
						User:            p.User,
						BinPath:         p.BinPath,
						CommandLine:     p.CommandLine,
						IntegrityLevel:  p.IntegrityLevel,
						StartTime:       int(p.StartTime),
					}
				}
				if _, err := mythicrpc.SendMythicRPCProcessCreate(mythicrpc.MythicRPCProcessCreateMessage{
					TaskID:    processResponse.TaskData.Task.ID,
					Processes: rpcProcesses,
				}); err != nil {
					logging.LogError(err, "Failed to populate process browser via RPC")
				}
			}

			// Update callback metadata if we find the callback's own process
			callbackPID := processResponse.TaskData.Callback.PID
			if callbackPID > 0 {
				for _, p := range processes {
					if p.ProcessID == callbackPID && p.Name != "" {
						update := mythicrpc.MythicRPCCallbackUpdateMessage{
							AgentCallbackID: &processResponse.TaskData.Callback.AgentCallbackID,
						}
						hasUpdate := false
						if p.Name != processResponse.TaskData.Callback.ProcessName {
							update.ProcessName = &p.Name
							hasUpdate = true
						}
						if p.Architecture != "" && p.Architecture != processResponse.TaskData.Callback.Architecture {
							update.Architecture = &p.Architecture
							hasUpdate = true
						}
						if hasUpdate {
							if _, err := mythicrpc.SendMythicRPCCallbackUpdate(update); err != nil {
								logging.LogError(err, "Failed to update callback metadata from ps")
							}
						}
						break
					}
				}
			}
			return response
		},
		TaskFunctionParseArgString: func(args *agentstructs.PTTaskMessageArgsData, input string) error {
			if input == "" {
				return nil
			}
			// Try JSON first, fall back to manual args for backward compat
			if err := args.LoadArgsFromJSONString(input); err != nil {
				args.SetManualArgs(input)
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
				OpsecPreMessage:    "OPSEC WARNING: Process listing enumerates all running processes including PIDs, users, and command lines. Common reconnaissance activity that may be baselined by EDR behavioral analytics.",
				OpsecPreBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionCreateTasking: func(task *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  task.Task.ID,
			}
			filter, _ := task.Args.GetStringArg("filter")
			pid, _ := parsePIDFromArg(task)
			ppid, _ := task.Args.GetNumberArg("ppid")
			user, _ := task.Args.GetStringArg("user")

			display := "Process list"
			if filter != "" {
				display += fmt.Sprintf(", filter=%s", filter)
			}
			if pid != 0 {
				display += fmt.Sprintf(", pid=%d", pid)
			}
			if ppid != 0 {
				display += fmt.Sprintf(", ppid=%d", int(ppid))
			}
			if user != "" {
				display += fmt.Sprintf(", user=%s", user)
			}
			response.DisplayParams = &display

			if displayParams, err := task.Args.GetFinalArgs(); err == nil && displayParams != "" && display == "Process list" {
				response.DisplayParams = &displayParams
			}
			return response
		},
	})
}
