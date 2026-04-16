package agentfunctions

import (
	"fmt"
	"path/filepath"
	"regexp"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

var sshExecutionRegex = regexp.MustCompile(`\[\*\]\s+SSH\s+(\S+)@(\S+)\s`)

func extractSSHExecutionInfo(responseText string) (user, host string, ok bool) {
	m := sshExecutionRegex.FindStringSubmatch(responseText)
	if len(m) > 2 {
		return m[1], m[2], true
	}
	return "", "", false
}

func sshAuthMethod(keyPath string) string {
	if keyPath != "" {
		return "key:" + keyPath
	}
	return "password"
}

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "ssh",
		Description:         "Execute commands, push files, or create SSH tunnels to remote hosts. Cross-platform lateral movement, tool transfer, and pivoting.",
		HelpString:          "ssh -host 192.168.1.1 -username root -password pass -command \"whoami\"\nssh -action push -host 10.0.0.1 -username root -key_path /root/.ssh/id_rsa -source /tmp/payload -destination /tmp/payload\nssh -action tunnel-local -host 10.0.0.1 -username root -password pass -local_port 8080 -remote_host 172.16.0.5 -remote_port 80\nssh -action tunnel-remote -host 10.0.0.1 -username root -password pass -remote_port 9090 -local_port 3389\nssh -action tunnel-dynamic -host 10.0.0.1 -username root -password pass -local_port 1080\nssh -action tunnel-list\nssh -action tunnel-stop -tunnel_id ssh-local-10.0.0.1-8080",
		Version:             3,
		MitreAttackMappings: []string{"T1021.004", "T1570", "T1572"}, // SSH + Lateral Tool Transfer + Protocol Tunneling
		Author:              "@galoryber",
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
				Description:      "exec: execute command (default). push: transfer file. check: validate SSH prerequisites. tunnel-local: local port forward (-L). tunnel-remote: remote port forward (-R). tunnel-dynamic: SOCKS proxy (-D). tunnel-list: show active tunnels. tunnel-stop: stop a tunnel.",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:          []string{"exec", "push", "check", "tunnel-local", "tunnel-remote", "tunnel-dynamic", "tunnel-list", "tunnel-stop"},
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
				Name:                 "username",
				CLIName:              "username",
				ModalDisplayName:     "Username",
				Description:          "SSH username",
				DynamicQueryFunction: getCallbackUserList,
				ParameterType:        agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:         "",
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
			{
				Name:             "local_port",
				CLIName:          "local_port",
				ModalDisplayName: "Local Port",
				Description:      "Local port to listen on (tunnel-local/dynamic) or forward to (tunnel-remote)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				DefaultValue:     0,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "remote_host",
				CLIName:          "remote_host",
				ModalDisplayName: "Remote Host (Tunnel Target)",
				Description:      "Target host to forward to through the SSH tunnel (tunnel-local only)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "remote_port",
				CLIName:          "remote_port",
				ModalDisplayName: "Remote Port",
				Description:      "Remote port (tunnel-local: target port; tunnel-remote: listen port on SSH host)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				DefaultValue:     0,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "bind_address",
				CLIName:          "bind_address",
				ModalDisplayName: "Bind Address",
				Description:      "Address to bind tunnel listener (default: 127.0.0.1, use 0.0.0.0 for all interfaces)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:     "127.0.0.1",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "tunnel_id",
				CLIName:          "tunnel_id",
				ModalDisplayName: "Tunnel ID",
				Description:      "ID of the tunnel to stop (shown by tunnel-list)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
		},
		AssociatedBrowserScript: &agentstructs.BrowserScript{ScriptPath: filepath.Join(".", "fawkes", "browserscripts", "ssh_new.js"), Author: "@galoryber"},
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
			switch {
			case action == "push":
				source, _ := taskData.Args.GetStringArg("source")
				msg += fmt.Sprintf(" Pushing local file '%s' to remote host — file write is a lateral tool transfer indicator (T1570).", source)
			case action == "tunnel-local" || action == "tunnel-remote" || action == "tunnel-dynamic":
				msg += " Creating SSH tunnel (T1572 Protocol Tunneling). Tunnel creates persistent TCP connections that may be detected by EDR/NTA."
				if action == "tunnel-local" {
					msg += " Local port forward opens a listening socket on the agent host."
				} else if action == "tunnel-dynamic" {
					msg += " SOCKS proxy opens a listening socket on the agent host."
				}
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

			if user, host, ok := extractSSHExecutionInfo(responseText); ok {
				createArtifact(processResponse.TaskData.Task.ID, "Remote Command",
					fmt.Sprintf("SSH execution: %s@%s", user, host))
				tagTask(processResponse.TaskData.Task.ID, "LATERAL",
					fmt.Sprintf("SSH execution on %s as %s", host, user))
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

			authMethod := sshAuthMethod(keyPath)

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
