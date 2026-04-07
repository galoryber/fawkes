package agentfunctions

import (
	"fmt"
	"regexp"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "ssh",
		Description:         "Execute commands on remote hosts via SSH with password or key-based authentication. Cross-platform lateral movement.",
		HelpString:          "ssh -host 192.168.1.1 -username root -password pass -command \"whoami\"\nssh -host 192.168.1.1 -username root -key_path /home/user/.ssh/id_rsa -command \"id\"\nssh -host 192.168.1.1 -username root -key_data \"-----BEGIN OPENSSH PRIVATE KEY-----...\" -command \"hostname\"",
		Version:             1,
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1021.004"}, // Remote Services: SSH
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{
				agentstructs.SUPPORTED_OS_WINDOWS,
				agentstructs.SUPPORTED_OS_LINUX,
				agentstructs.SUPPORTED_OS_MACOS,
			},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:                 "host",
				CLIName:              "host",
				ModalDisplayName:     "Target Host",
				Description:          "Remote host IP or hostname",
				ParameterType:        agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:         "",
				DynamicQueryFunction: getActiveHostList,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: true, GroupName: "Default"},
				},
			},
			{
				Name:             "username",
				CLIName:          "username",
				ModalDisplayName: "Username",
				Description:      "SSH username",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: true, GroupName: "Default"},
				},
			},
			{
				Name:             "command",
				CLIName:          "command",
				ModalDisplayName: "Command",
				Description:      "Command to execute on the remote host",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: true, GroupName: "Default"},
				},
			},
			{
				Name:             "password",
				CLIName:          "password",
				ModalDisplayName: "Password",
				Description:      "Password for SSH auth (also used as key passphrase if key is encrypted)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "key_path",
				CLIName:          "key_path",
				ModalDisplayName: "Key File Path",
				Description:      "Path to SSH private key on the agent's filesystem (e.g., /home/user/.ssh/id_rsa)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "key_data",
				CLIName:          "key_data",
				ModalDisplayName: "Key Data (PEM)",
				Description:      "Inline SSH private key in PEM format",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "port",
				CLIName:          "port",
				ModalDisplayName: "SSH Port",
				Description:      "SSH port (default: 22)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				DefaultValue:     22,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "timeout",
				CLIName:          "timeout",
				ModalDisplayName: "Timeout (seconds)",
				Description:      "Connection and command timeout in seconds (default: 60)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				DefaultValue:     60,
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
		TaskFunctionOPSECPre: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTTaskOPSECPreTaskMessageResponse {
			host, _ := taskData.Args.GetStringArg("host")
			username, _ := taskData.Args.GetStringArg("username")
			return agentstructs.PTTTaskOPSECPreTaskMessageResponse{
				TaskID:             taskData.Task.ID,
				Success:            true,
				OpsecPreBlocked:    false,
				OpsecPreMessage:    fmt.Sprintf("OPSEC WARNING: SSH command execution as %s on %s. SSH sessions are logged in auth.log/secure and may generate audit events. Connection metadata (source IP, username, key fingerprint) is recorded by sshd.", username, host),
				OpsecPreBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionOPSECPost: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskOPSECPostTaskMessageResponse {
			return agentstructs.PTTaskOPSECPostTaskMessageResponse{
				TaskID:              taskData.Task.ID,
				Success:             true,
				OpsecPostBlocked:    false,
				OpsecPostMessage:    "OPSEC AUDIT: SSH command executed on remote host. SSH session logged in /var/log/auth.log (Linux) or /var/log/secure. Command may appear in remote host's shell history. Connection metadata (source IP, user) recorded in sshd logs.",
				OpsecPostBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
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
			// Parse: [*] SSH user@host:port (auth: method)
			re := regexp.MustCompile(`\[\*\]\s+SSH\s+(\S+)@(\S+)\s`)
			if m := re.FindStringSubmatch(responseText); len(m) > 2 {
				createArtifact(processResponse.TaskData.Task.ID, "Remote Command",
					fmt.Sprintf("SSH execution: %s@%s", m[1], m[2]))
			}
			return response
		},
		TaskFunctionCreateTasking: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  taskData.Task.ID,
			}

			host, _ := taskData.Args.GetStringArg("host")
			username, _ := taskData.Args.GetStringArg("username")
			command, _ := taskData.Args.GetStringArg("command")
			keyPath, _ := taskData.Args.GetStringArg("key_path")

			authMethod := "password"
			if keyPath != "" {
				authMethod = "key:" + keyPath
			}

			displayMsg := fmt.Sprintf("SSH %s@%s (%s): %s", username, host, authMethod, command)
			response.DisplayParams = &displayMsg

			createArtifact(taskData.Task.ID, "API Call",
				fmt.Sprintf("SSH command execution on %s@%s: %s", username, host, command))
			logOperationEvent(taskData.Task.ID,
				fmt.Sprintf("[LATERAL] ssh-exec: remote execution as %s@%s from %s", username, host, taskData.Callback.Host), true)

			return response
		},
	})
}
