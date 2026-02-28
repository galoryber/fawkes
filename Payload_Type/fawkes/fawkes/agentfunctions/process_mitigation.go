package agentfunctions

import (
	"fmt"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "process-mitigation",
		Description:         "Query or set Windows process mitigation policies (DEP, ASLR, CIG, ACG, CFG). Set CIG to block unsigned DLL loading (EDR injection defense).",
		HelpString:          "process-mitigation\nprocess-mitigation -action query\nprocess-mitigation -action query -pid 1234\nprocess-mitigation -action set -policy cig",
		Version:             1,
		SupportedUIFeatures: []string{},
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1480"},
		ScriptOnlyCommand:   false,
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_WINDOWS},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:             "action",
				ModalDisplayName: "Action",
				CLIName:          "action",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Description:      "query: list all mitigation policies. set: enable a specific policy on the current process.",
				DefaultValue:     "query",
				Choices:          []string{"query", "set"},
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
						UIModalPosition:     0,
					},
				},
			},
			{
				Name:             "pid",
				ModalDisplayName: "Target PID",
				CLIName:          "pid",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				Description:      "Process ID to query (0 or omit for self). Only used with query action.",
				DefaultValue:     0,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
						UIModalPosition:     1,
					},
				},
			},
			{
				Name:             "policy",
				ModalDisplayName: "Policy to Set",
				CLIName:          "policy",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Description:      "Policy to enable (only used with set action). cig=block unsigned DLLs, acg=block dynamic code, child-block=prevent child processes.",
				DefaultValue:     "cig",
				Choices:          []string{"cig", "acg", "child-block", "dep", "cfg", "ext-disable", "image-restrict", "font-disable"},
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
						UIModalPosition:     2,
					},
				},
			},
		},
		TaskFunctionParseArgString: func(args *agentstructs.PTTaskMessageArgsData, input string) error {
			if input != "" {
				return args.LoadArgsFromJSONString(input)
			}
			return nil
		},
		TaskFunctionParseArgDictionary: func(args *agentstructs.PTTaskMessageArgsData, input map[string]interface{}) error {
			return args.LoadArgsFromDictionary(input)
		},
		TaskFunctionCreateTasking: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  taskData.Task.ID,
			}
			action, _ := taskData.Args.GetStringArg("action")
			if action == "" {
				action = "query"
			}
			switch action {
			case "query":
				pid, _ := taskData.Args.GetNumberArg("pid")
				if pid > 0 {
					createArtifact(taskData.Task.ID, "API Call",
						fmt.Sprintf("GetProcessMitigationPolicy(PID %d)", int(pid)))
				} else {
					createArtifact(taskData.Task.ID, "API Call",
						"GetProcessMitigationPolicy(self)")
				}
			case "set":
				policy, _ := taskData.Args.GetStringArg("policy")
				createArtifact(taskData.Task.ID, "API Call",
					fmt.Sprintf("SetProcessMitigationPolicy(%s)", policy))
			}
			if displayParams, err := taskData.Args.GetFinalArgs(); err == nil && displayParams != "" {
				response.DisplayParams = &displayParams
			}
			return response
		},
		TaskFunctionProcessResponse: nil,
	})
}
