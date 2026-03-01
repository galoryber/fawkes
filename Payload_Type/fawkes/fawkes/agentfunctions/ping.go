package agentfunctions

import (
	"fmt"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "ping",
		Description:         "TCP connect host reachability check with subnet sweep. Probes specified port to determine if hosts are alive. Supports CIDR, dash ranges, and comma-separated lists.",
		HelpString:          "ping -hosts 192.168.1.1\nping -hosts 192.168.1.0/24 -port 445 -timeout 1000 -threads 25\nping -hosts 10.0.0.1-50 -port 22\nping -hosts dc01,dc02,web01 -port 389",
		Version:             1,
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1018"},
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{
				agentstructs.SUPPORTED_OS_WINDOWS,
				agentstructs.SUPPORTED_OS_LINUX,
				agentstructs.SUPPORTED_OS_MACOS,
			},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:          "hosts",
				CLIName:       "hosts",
				Description:   "Target host(s) — single IP, comma-separated, CIDR (192.168.1.0/24), or dash range (192.168.1.1-254)",
				DefaultValue:  "",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: true, GroupName: "Default"},
				},
			},
			{
				Name:          "port",
				CLIName:       "port",
				Description:   "TCP port to probe (default: 445)",
				DefaultValue:  445,
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:          "timeout",
				CLIName:       "timeout",
				Description:   "Timeout per host in milliseconds (default: 1000)",
				DefaultValue:  1000,
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:          "threads",
				CLIName:       "threads",
				Description:   "Concurrent connections (default: 25, max: 100)",
				DefaultValue:  25,
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
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
		TaskFunctionCreateTasking: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{Success: true, TaskID: taskData.Task.ID}
			hosts, _ := taskData.Args.GetStringArg("hosts")
			display := fmt.Sprintf("%s", hosts)
			response.DisplayParams = &display
			return response
		},
	})
}
