package agentfunctions

import (
	"fmt"
	"strconv"
	"strings"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "pipe-server",
		Description:         "Named pipe impersonation — create pipe server, wait for privileged client, impersonate token (T1134.001)",
		HelpString:          "pipe-server -action <check|impersonate> [-name <pipe_name>] [-timeout 30]",
		Version:             1,
		SupportedUIFeatures: []string{},
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1134.001"},
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
				Choices:          []string{"check", "impersonate"},
				Description:      "check: enumerate pipe privesc opportunities. impersonate: create pipe and wait for client.",
				DefaultValue:     "impersonate",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "name",
				ModalDisplayName: "Pipe Name",
				CLIName:          "name",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Named pipe name (without \\\\.\\pipe\\ prefix). Random if empty.",
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "timeout",
				ModalDisplayName: "Timeout (seconds)",
				CLIName:          "timeout",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				Description:      "How long to wait for a client connection (default: 30 seconds)",
				DefaultValue:     30,
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
			// Try JSON first (from API/modal)
			if err := args.LoadArgsFromJSONString(input); err == nil {
				return nil
			}
			// Plain text: parse -flag value pairs
			parts := strings.Fields(input)
			for i := 0; i < len(parts); i++ {
				switch parts[i] {
				case "-action":
					if i+1 < len(parts) {
						i++
						args.SetArgValue("action", parts[i])
					}
				case "-name", "-pipe_name":
					if i+1 < len(parts) {
						i++
						args.SetArgValue("name", parts[i])
					}
				case "-timeout":
					if i+1 < len(parts) {
						i++
						if t, err := strconv.Atoi(parts[i]); err == nil {
							args.SetArgValue("timeout", t)
						}
					}
				default:
					// Single word without flag — treat as pipe name
					if !strings.HasPrefix(parts[i], "-") {
						args.SetArgValue("name", parts[i])
					}
				}
			}
			return nil
		},
		TaskFunctionParseArgDictionary: func(args *agentstructs.PTTaskMessageArgsData, input map[string]interface{}) error {
			return args.LoadArgsFromDictionary(input)
		},
		TaskFunctionOPSECPre: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTTaskOPSECPreTaskMessageResponse {
			action, _ := taskData.Args.GetStringArg("action")
			msg := "OPSEC WARNING: Named pipe server operation. "
			if action == "impersonate" {
				msg += "Token impersonation via named pipe is a well-known privilege escalation technique (T1134.001). EDR may alert on ImpersonateNamedPipeClient API calls and token manipulation."
			} else {
				msg += "Creating a named pipe listener may be detected by pipe enumeration or Sysmon EventID 17/18 (Pipe Created/Connected)."
			}
			return agentstructs.PTTTaskOPSECPreTaskMessageResponse{
				TaskID:             taskData.Task.ID,
				Success:            true,
				OpsecPreBlocked:    false,
				OpsecPreMessage:    msg,
				OpsecPreBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionCreateTasking: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  taskData.Task.ID,
			}
			action, _ := taskData.Args.GetStringArg("action")
			display := action
			name, _ := taskData.Args.GetStringArg("name")
			if name != "" {
				display += fmt.Sprintf(" %s", name)
			}
			response.DisplayParams = &display
			if action == "impersonate" {
				pipeName := name
				if pipeName == "" {
					pipeName = "fawkes_pipe"
				}
				createArtifact(taskData.Task.ID, "API Call", fmt.Sprintf("CreateNamedPipe(\\\\.\\pipe\\%s) + ImpersonateNamedPipeClient", pipeName))
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
			action, _ := processResponse.TaskData.Args.GetStringArg("action")
			if action == "impersonate" && (strings.Contains(responseText, "impersonat") || strings.Contains(responseText, "SYSTEM") || strings.Contains(responseText, "success")) {
				tagTask(processResponse.TaskData.Task.ID, "ELEVATED",
					"Named pipe impersonation successful (T1134.001)")
			}
			return response
		},
	})
}
