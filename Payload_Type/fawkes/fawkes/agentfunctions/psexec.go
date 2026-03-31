package agentfunctions

import (
	"fmt"
	"regexp"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "psexec",
		Description:         "Execute commands on remote hosts via SCM service creation — PSExec-style lateral movement (T1021.002, T1569.002)",
		HelpString:          "psexec -host <target> -command <cmd> [-name <svcname>] [-display <displayname>] [-cleanup <true|false>]",
		Version:             1,
		SupportedUIFeatures: []string{},
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1021.002", "T1569.002"},
		ScriptOnlyCommand:   false,
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS:                []string{agentstructs.SUPPORTED_OS_WINDOWS},
			CommandCanOnlyBeLoadedLater: true,
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:             "host",
				ModalDisplayName: "Target Host",
				CLIName:          "host",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Target hostname or IP address",
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: true,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "command",
				ModalDisplayName: "Command",
				CLIName:          "command",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Command to execute on the remote host (automatically wrapped in cmd.exe /c)",
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: true,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "name",
				ModalDisplayName: "Service Name",
				CLIName:          "name",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Custom service name (optional — random name generated if not specified)",
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "display",
				ModalDisplayName: "Display Name",
				CLIName:          "display",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Service display name (optional — uses service name if not specified)",
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "cleanup",
				ModalDisplayName: "Cleanup",
				CLIName:          "cleanup",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:          []string{"true", "false"},
				Description:      "Delete the service after execution (default: true)",
				DefaultValue:     "true",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
		},
		AssociatedBrowserScript: nil,
		TaskFunctionOPSECPre: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTTaskOPSECPreTaskMessageResponse {
			host, _ := taskData.Args.GetStringArg("host")
			return agentstructs.PTTTaskOPSECPreTaskMessageResponse{
				TaskID:  taskData.Task.ID,
				Success: true,
				OpsecPreBlocked: false,
				OpsecPreMessage: fmt.Sprintf("OPSEC WARNING: PsExec creates a service on remote host %s. "+
					"Artifacts: SCM connection (Event 7045), service creation, cmd.exe child process. "+
					"Heavy footprint — consider WMI or WinRM for stealthier lateral movement.", host),
				OpsecPreBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionOPSECPost: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskOPSECPostTaskMessageResponse {
			host, _ := taskData.Args.GetStringArg("host")
			return agentstructs.PTTaskOPSECPostTaskMessageResponse{
				TaskID:              taskData.Task.ID,
				Success:             true,
				OpsecPostBlocked:    false,
				OpsecPostMessage:    fmt.Sprintf("OPSEC AUDIT: PsExec lateral movement to %s configured. Service creation and SMB artifacts will be generated.", host),
				OpsecPostBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
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
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  taskData.Task.ID,
			}
			host, _ := taskData.Args.GetStringArg("host")
			command, _ := taskData.Args.GetStringArg("command")
			display := fmt.Sprintf("%s → %s", host, command)
			response.DisplayParams = &display
			createArtifact(taskData.Task.ID, "API Call", fmt.Sprintf("SCM ConnectRemote(%s) CreateService binpath=cmd.exe /c %s", host, command))
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
			// Parse: PSExec on <host>: and Service: <name>
			hostRe := regexp.MustCompile(`PSExec on (\S+?):`)
			svcRe := regexp.MustCompile(`Service:\s+(\S+)`)
			host := "unknown"
			service := "unknown"
			if m := hostRe.FindStringSubmatch(responseText); len(m) > 1 {
				host = m[1]
			}
			if m := svcRe.FindStringSubmatch(responseText); len(m) > 1 {
				service = m[1]
			}
			if host != "unknown" {
				createArtifact(processResponse.TaskData.Task.ID, "Remote Command",
					fmt.Sprintf("PSExec on %s (service: %s)", host, service))
				createArtifact(processResponse.TaskData.Task.ID, "Remote Service",
					fmt.Sprintf("SCM service '%s' on %s", service, host))
			}
			return response
		},
	})
}
