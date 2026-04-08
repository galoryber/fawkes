package agentfunctions

import (
	"fmt"
	"regexp"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "ssh",
		Description:         "Execute commands or push files to remote hosts via SSH. Cross-platform lateral movement and tool transfer.",
		HelpString:          "ssh -host 192.168.1.1 -username root -password pass -command \"whoami\"\nssh -host 192.168.1.1 -username root -key_path /home/user/.ssh/id_rsa -command \"id\"\nssh -action push -host 192.168.1.1 -username root -password pass -source /tmp/payload -destination /tmp/payload",
		Version:             2,
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1021.004", "T1570"}, // Remote Services: SSH + Lateral Tool Transfer
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{
				agentstructs.SUPPORTED_OS_WINDOWS,
				agentstructs.SUPPORTED_OS_LINUX,
				agentstructs.SUPPORTED_OS_MACOS,
			},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:             "action",
				CLIName:          "action",
				ModalDisplayName: "Action",
				Description:      "exec: execute command (default). push: transfer a local file to the remote host.",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:          []string{"exec", "push"},
				DefaultValue:     "exec",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
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
				Description:      "Command to execute on the remote host (for exec action)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
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
				Description:      "Path to SSH private key on the agent's filesystem",
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
				Name:             "source",
				CLIName:          "source",
				ModalDisplayName: "Source File (Local)",
				Description:      "Local file path on the agent to push to the remote host (for push action)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "destination",
				CLIName:          "destination",
				ModalDisplayName: "Destination Path (Remote)",
				Description:      "Remote file path to write to (for push action)",
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
			action, _ := taskData.Args.GetStringArg("action")

			msg := fmt.Sprintf("OPSEC WARNING: SSH %s as %s on %s.", action, username, host)
			if action == "push" {
				source, _ := taskData.Args.GetStringArg("source")
				msg += fmt.Sprintf(" Pushing local file '%s' to remote host — file write is a lateral tool transfer indicator (T1570).", source)
			}
			msg += " SSH sessions are logged in auth.log/secure. Connection metadata (source IP, username, key fingerprint) is recorded by sshd."

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
			msg := "OPSEC AUDIT: SSH session logged in /var/log/auth.log (Linux) or /var/log/secure."
			if action == "push" {
				msg += " File written to remote host. Check remote filesystem for transferred file."
			} else {
				msg += " Command may appear in remote host's shell history."
			}
			msg += " Connection metadata (source IP, user) recorded in sshd logs."

			return agentstructs.PTTaskOPSECPostTaskMessageResponse{
				TaskID:              taskData.Task.ID,
				Success:             true,
				OpsecPostBlocked:    false,
				OpsecPostMessage:    msg,
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

			action, _ := processResponse.TaskData.Args.GetStringArg("action")

			if action == "push" {
				// Track file push as lateral tool transfer
				host, _ := processResponse.TaskData.Args.GetStringArg("host")
				destination, _ := processResponse.TaskData.Args.GetStringArg("destination")
				createArtifact(processResponse.TaskData.Task.ID, "File Write",
					fmt.Sprintf("SSH file push to %s:%s", host, destination))
				tagTask(processResponse.TaskData.Task.ID, "LATERAL",
					fmt.Sprintf("SSH file push to %s", host))
				return response
			}

			// Parse: [*] SSH user@host:port (auth: method)
			re := regexp.MustCompile(`\[\*\]\s+SSH\s+(\S+)@(\S+)\s`)
			if m := re.FindStringSubmatch(responseText); len(m) > 2 {
				createArtifact(processResponse.TaskData.Task.ID, "Remote Command",
					fmt.Sprintf("SSH execution: %s@%s", m[1], m[2]))
				tagTask(processResponse.TaskData.Task.ID, "LATERAL",
					fmt.Sprintf("SSH execution on %s as %s", m[2], m[1]))
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
			action, _ := taskData.Args.GetStringArg("action")
			keyPath, _ := taskData.Args.GetStringArg("key_path")

			authMethod := "password"
			if keyPath != "" {
				authMethod = "key:" + keyPath
			}

			if action == "push" {
				source, _ := taskData.Args.GetStringArg("source")
				destination, _ := taskData.Args.GetStringArg("destination")
				displayMsg := fmt.Sprintf("SSH push %s → %s@%s:%s (%s)", source, username, host, destination, authMethod)
				response.DisplayParams = &displayMsg
				createArtifact(taskData.Task.ID, "API Call",
					fmt.Sprintf("SSH file transfer to %s@%s:%s", username, host, destination))
				logOperationEvent(taskData.Task.ID,
					fmt.Sprintf("[LATERAL TOOL TRANSFER] SSH push to %s@%s:%s from %s", username, host, destination, taskData.Callback.Host), false)
			} else {
				command, _ := taskData.Args.GetStringArg("command")
				displayMsg := fmt.Sprintf("SSH %s@%s (%s): %s", username, host, authMethod, command)
				response.DisplayParams = &displayMsg
				createArtifact(taskData.Task.ID, "API Call",
					fmt.Sprintf("SSH command execution on %s@%s: %s", username, host, command))
				logOperationEvent(taskData.Task.ID,
					fmt.Sprintf("[LATERAL] ssh-exec: remote execution as %s@%s from %s", username, host, taskData.Callback.Host), true)
			}

			return response
		},
	})
}
