package agentfunctions

import (
	"encoding/json"
	"fmt"
	"path/filepath"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name: "drivers",
		AssociatedBrowserScript: &agentstructs.BrowserScript{
			ScriptPath: filepath.Join(".", "fawkes", "browserscripts", "drivers_new.js"),
			Author:     "@galoryber",
		},
		Description:         "drivers [-filter name] - Enumerate loaded kernel drivers and modules. Windows: EnumDeviceDrivers API. Linux: /proc/modules. macOS: kext/system extension enumeration.",
		HelpString:          "drivers [-filter name]",
		Version:             1,
		MitreAttackMappings: []string{"T1082"}, // System Information Discovery
		Author:              "@galoryber",
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_LINUX, agentstructs.SUPPORTED_OS_MACOS, agentstructs.SUPPORTED_OS_WINDOWS},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:          "filter",
				CLIName:       "filter",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:   "Optional name filter (case-insensitive substring match)",
				DefaultValue:  "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						UIModalPosition:     1,
						GroupName:           "Default",
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
			return agentstructs.PTTTaskOPSECPreTaskMessageResponse{
				TaskID:             taskData.Task.ID,
				Success:            true,
				OpsecPreBlocked:    false,
				OpsecPreMessage:    "OPSEC WARNING: Driver enumeration lists loaded kernel drivers including security products (EDR, AV kernel components). Commonly used for defense evasion reconnaissance — may be flagged by EDR behavioral analytics.",
				OpsecPreBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionProcessResponse: func(processResponse agentstructs.PtTaskProcessResponseMessage) agentstructs.PTTaskProcessResponseMessageResponse {
			response := agentstructs.PTTaskProcessResponseMessageResponse{
				TaskID:  processResponse.TaskData.Task.ID,
				Success: true,
			}
			responseText, ok := processResponse.Response.(string)
			if !ok || responseText == "" || responseText == "[]" {
				return response
			}
			type driverEntry struct {
				Name    string `json:"name"`
				Path    string `json:"path"`
				Status  string `json:"status"`
				Size    int64  `json:"size"`
				Version string `json:"version"`
			}
			var entries []driverEntry
			if err := json.Unmarshal([]byte(responseText), &entries); err != nil {
				return response
			}
			for _, e := range entries {
				createArtifact(processResponse.TaskData.Task.ID, "Configuration",
					fmt.Sprintf("Driver: %s (%s) — %s", e.Name, e.Path, e.Status))
			}
			return response
		},
		TaskFunctionOPSECPost: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskOPSECPostTaskMessageResponse {
			return agentstructs.PTTaskOPSECPostTaskMessageResponse{
				TaskID:              taskData.Task.ID,
				Success:             true,
				OpsecPostBlocked:    false,
				OpsecPostMessage:    "OPSEC AUDIT: Driver enumeration completed. Loaded drivers reveal security products (e.g., crowdstrike, sentinel, cylance kernel drivers). EnumDeviceDrivers API call may be logged by EDR. Results inform evasion planning — be aware that querying drivers is itself a reconnaissance indicator.",
				OpsecPostBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionCreateTasking: func(task *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  task.Task.ID,
			}
			if displayParams, err := task.Args.GetFinalArgs(); err == nil && displayParams != "" {
				response.DisplayParams = &displayParams
			}
			return response
		},
	})
}
