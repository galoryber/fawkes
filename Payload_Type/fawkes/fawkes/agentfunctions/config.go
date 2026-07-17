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
		Name:                "config",
		Description:         "View or modify runtime agent configuration, or update the agent binary",
		HelpString:          "config [-action show|set|update] [-key sleep|jitter|killdate|working_hours_start|working_hours_end|working_days] [-value <value>] [-file <file_id>] [-hash <sha256>]",
		Version:             2,
		MitreAttackMappings: []string{},
		SupportedUIFeatures: []string{},
		Author:              "@galoryber",
		AssociatedBrowserScript: &agentstructs.BrowserScript{
			ScriptPath: filepath.Join(".", "fawkes", "browserscripts", "config_new.js"),
			Author:     "@galoryber",
		},
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS:        []string{agentstructs.SUPPORTED_OS_WINDOWS, agentstructs.SUPPORTED_OS_LINUX, agentstructs.SUPPORTED_OS_MACOS},
			CommandIsSuggested: true,
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:          "action",
				CLIName:       "action",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Description:   "Action: show current config, set a value, or update the agent binary",
				Choices:       []string{"show", "set", "update"},
				DefaultValue:  "show",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
					{
						ParameterIsRequired: true,
						GroupName:           "Update",
					},
				},
			},
			{
				Name:          "key",
				CLIName:       "key",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Description:   "Config key to modify",
				Choices:       []string{"sleep", "jitter", "killdate", "working_hours_start", "working_hours_end", "working_days"},
				DefaultValue:  "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:          "value",
				CLIName:       "value",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:   "New value for the config key",
				DefaultValue:  "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:          "file",
				CLIName:       "file",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_FILE,
				Description:   "New payload binary to replace the running agent (Mythic file upload)",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: true,
						GroupName:           "Update",
					},
				},
			},
			{
				Name:          "hash",
				CLIName:       "hash",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:   "Expected SHA256 hash of the new binary (optional integrity check)",
				DefaultValue:  "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Update",
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
			action, _ := taskData.Args.GetStringArg("action")
			var msg string
			switch action {
			case "set":
				key, _ := taskData.Args.GetStringArg("key")
				msg = fmt.Sprintf("OPSEC WARNING: Modifying agent config key '%s'. Config changes alter C2 behavior and may affect detection profile (e.g., reducing sleep increases network traffic).", key)
			case "update":
				msg = "OPSEC WARNING: Agent self-update will write a new binary to disk and spawn a new process. " +
					"This creates: (1) file write artifact in temp directory, (2) new process creation event, " +
					"(3) current agent process exit. The new binary creates a separate callback. " +
					"EDR may flag the process chain (parent writes child binary then exits)."
			default:
				msg = "OPSEC WARNING: Viewing agent runtime configuration."
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
			action, _ := taskData.Args.GetStringArg("action")
			var msg string
			switch action {
			case "update":
				msg = "OPSEC AUDIT: Agent binary update performed. New binary written to disk and launched. " +
					"Old process will exit. Clean up: verify old binary is deleted, check for process creation events " +
					"in Sysmon EID 1 / ETW, and confirm new callback established."
			default:
				msg = "OPSEC AUDIT: Agent configuration accessed or changed. Changes are logged in Mythic."
			}
			return agentstructs.PTTaskOPSECPostTaskMessageResponse{
				TaskID:              taskData.Task.ID,
				Success:             true,
				OpsecPostBlocked:    false,
				OpsecPostMessage:    msg,
				OpsecPostBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionCreateTasking: func(task *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  task.Task.ID,
			}
			action, _ := task.Args.GetStringArg("action")
			display := action
			if action == "update" {
				display = "update (self-update agent binary)"
			}
			response.DisplayParams = &display
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
			if !strings.Contains(responseText, "self-update") && !strings.Contains(responseText, "Launching new agent") {
				return response
			}
			logOperationEvent(processResponse.TaskData.Task.ID,
				"[AGENT UPDATE] Agent self-update initiated — new binary downloaded and launched, current agent exiting",
				false)
			var hash string
			for _, line := range strings.Split(responseText, "\n") {
				if strings.Contains(line, "SHA256:") {
					parts := strings.SplitN(line, "SHA256:", 2)
					if len(parts) == 2 {
						hash = strings.TrimSpace(parts[1])
					}
				}
			}
			if hash != "" {
				mythicrpc.SendMythicRPCArtifactCreate(mythicrpc.MythicRPCArtifactCreateMessage{
					TaskID:           processResponse.TaskData.Task.ID,
					BaseArtifactType: "File Write",
					ArtifactMessage:  fmt.Sprintf("Agent self-update binary written to temp directory (SHA256: %s)", hash),
				})
			}
			mythicrpc.SendMythicRPCArtifactCreate(mythicrpc.MythicRPCArtifactCreateMessage{
				TaskID:           processResponse.TaskData.Task.ID,
				BaseArtifactType: "Process Create",
				ArtifactMessage:  "New agent process spawned (detached/new session) as part of self-update",
			})
			return response
		},
	})
}
