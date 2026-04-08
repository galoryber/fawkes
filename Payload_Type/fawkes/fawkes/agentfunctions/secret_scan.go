package agentfunctions

import (
	"fmt"
	"path/filepath"
	"strings"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
	"github.com/MythicMeta/MythicContainer/mythicrpc"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name: "secret-scan",
		AssociatedBrowserScript: &agentstructs.BrowserScript{
			ScriptPath: filepath.Join(".", "fawkes", "browserscripts", "secret_scan_new.js"),
			Author:     "@galoryber",
		},
		Description:         "Search files for secrets, API keys, private keys, and sensitive patterns (T1552.001, T1005)",
		HelpString:          "secret-scan [-path /home/user] [-depth 5] [-max_results 100]",
		Version:             2,
		SupportedUIFeatures: []string{"file_browser:list"},
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1552.001", "T1005"},
		ScriptOnlyCommand:   false,
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_WINDOWS, agentstructs.SUPPORTED_OS_LINUX, agentstructs.SUPPORTED_OS_MACOS},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:             "path",
				ModalDisplayName: "Search Path",
				CLIName:          "path",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Root directory to scan (default: user home directory)",
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "depth",
				ModalDisplayName: "Search Depth",
				CLIName:          "depth",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				Description:      "Maximum directory recursion depth (default 5)",
				DefaultValue:     5,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "max_results",
				ModalDisplayName: "Max Results",
				CLIName:          "max_results",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				Description:      "Maximum number of findings to return (default 100)",
				DefaultValue:     100,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
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
				OpsecPreMessage:    "OPSEC WARNING: Secret scanning reads and regex-matches file contents across directories. High I/O file access patterns (bulk reads) may trigger endpoint behavioral analytics or file access auditing.",
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
			host := processResponse.TaskData.Callback.Host

			// Count findings by type from the text output format: "[TYPE] file:line"
			findingCount := 0
			for _, line := range strings.Split(responseText, "\n") {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "[") && strings.Contains(line, "]") {
					findingCount++
				}
			}

			if findingCount > 0 {
				mythicrpc.SendMythicRPCArtifactCreate(mythicrpc.MythicRPCArtifactCreateMessage{
					TaskID:           processResponse.TaskData.Task.ID,
					BaseArtifactType: "Credential Access",
					ArtifactMessage:  fmt.Sprintf("Secret scan found %d secrets on %s", findingCount, host),
				})
				tagTask(processResponse.TaskData.Task.ID, "PLAINTEXT",
					fmt.Sprintf("%d secrets discovered on %s", findingCount, host))
				logOperationEvent(processResponse.TaskData.Task.ID,
					fmt.Sprintf("[CREDENTIAL ACCESS] Secret scan found %d secrets on %s", findingCount, host), true)
			}
			return response
		},
		TaskFunctionCreateTasking: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  taskData.Task.ID,
			}
			createArtifact(taskData.Task.ID, "File Read", "Scanning files for secret patterns")
			return response
		},
	})
}
