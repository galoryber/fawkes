package agentfunctions

import (
	"fmt"
	"regexp"
	"strings"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "mem-scan",
		Description:         "mem-scan -pid <pid> -pattern <string> [-hex] [-max_results 50] [-context_bytes 32] - Search process memory for strings or byte patterns. Cross-platform using ReadProcessMemory (Windows) or /proc/pid/mem (Linux).",
		HelpString:          "mem-scan -pid <pid> -pattern <string> [-hex] [-max_results 50] [-context_bytes 32]",
		Version:             1,
		MitreAttackMappings: []string{"T1005", "T1057"}, // Data from Local System + Process Discovery
		Author:              "@galoryber",
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_LINUX, agentstructs.SUPPORTED_OS_WINDOWS},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:          "pid",
				CLIName:       "pid",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				Description:   "Target process ID to scan (0 = current process)",
				DefaultValue:  0,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: true,
						UIModalPosition:     1,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:          "pattern",
				CLIName:       "pattern",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:   "String pattern to search for (or hex bytes if -hex is set, e.g. '4d5a9000')",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: true,
						UIModalPosition:     2,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:          "hex",
				CLIName:       "hex",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_BOOLEAN,
				Description:   "Interpret pattern as hex bytes (e.g. '4d5a9000')",
				DefaultValue:  false,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     3,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:          "max_results",
				CLIName:       "max_results",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				Description:   "Maximum number of matches to return (default: 50)",
				DefaultValue:  50,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     4,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:          "context_bytes",
				CLIName:       "context_bytes",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				Description:   "Bytes of context to show around each match (default: 32)",
				DefaultValue:  32,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     5,
						GroupName:           "Default",
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
		TaskFunctionOPSECPre: func(task *agentstructs.PTTaskMessageAllData) agentstructs.PTTTaskOPSECPreTaskMessageResponse {
			return agentstructs.PTTTaskOPSECPreTaskMessageResponse{
				TaskID:             task.Task.ID,
				Success:            true,
				OpsecPreBlocked:    false,
				OpsecPreMessage:    "OPSEC WARNING: Process memory scanning uses ReadProcessMemory/VirtualQueryEx (Windows) or /proc/pid/mem (Linux). Cross-process memory access is a high-fidelity indicator monitored by EDR products. Scanning LSASS or security tool processes will likely trigger alerts.",
				OpsecPreBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
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
			// Parse match count and PID from output header
			matchRe := regexp.MustCompile(`Matches found:\s*(\d+)`)
			pidRe := regexp.MustCompile(`Memory Scan: PID (\d+)`)
			patternRe := regexp.MustCompile(`Pattern:\s*(.+?)\s*\(`)

			matchCount := "0"
			pid := "unknown"
			pattern := "unknown"

			if m := matchRe.FindStringSubmatch(responseText); len(m) > 1 {
				matchCount = m[1]
			}
			if m := pidRe.FindStringSubmatch(responseText); len(m) > 1 {
				pid = m[1]
			}
			if m := patternRe.FindStringSubmatch(responseText); len(m) > 1 {
				pattern = strings.TrimSpace(m[1])
			}

			if matchCount != "0" {
				createArtifact(processResponse.TaskData.Task.ID, "Process Memory Scan",
					fmt.Sprintf("Memory scan PID %s: %s matches for pattern '%s'", pid, matchCount, pattern))
			}
			return response
		},
		TaskFunctionCreateTasking: func(task *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  task.Task.ID,
			}
			createArtifact(task.Task.ID, "API Call", "ReadProcessMemory / VirtualQueryEx (process memory scan)")
			if displayParams, err := task.Args.GetFinalArgs(); err == nil && displayParams != "" {
				response.DisplayParams = &displayParams
			}
			return response
		},
	})
}
