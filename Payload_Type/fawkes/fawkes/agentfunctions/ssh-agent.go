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
		Name:                "ssh-agent",
		Description:         "Enumerate SSH agent sockets and list loaded keys for lateral movement (T1552.004)",
		HelpString:          "ssh-agent [-action <list|enum>] [-socket /path/to/agent.sock]",
		Version:             1,
		SupportedUIFeatures: []string{},
		Author:              "@galoryber",
		AssociatedBrowserScript: &agentstructs.BrowserScript{
			ScriptPath: filepath.Join(".", "fawkes", "browserscripts", "ssh_agent_new.js"),
			Author:     "@galoryber",
		},
		MitreAttackMappings: []string{"T1552.004"},
		ScriptOnlyCommand:   false,
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{agentstructs.SUPPORTED_OS_LINUX, agentstructs.SUPPORTED_OS_MACOS},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:             "action",
				ModalDisplayName: "Action",
				CLIName:          "action",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:          []string{"list", "enum"},
				Description:      "list: connect to agents and list loaded keys. enum: find agent sockets without connecting.",
				DefaultValue:     "list",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{
						ParameterIsRequired: false,
						GroupName:           "Default",
					},
				},
			},
			{
				Name:             "socket",
				ModalDisplayName: "Socket Path",
				CLIName:          "socket",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Optional: path to a specific SSH agent socket (e.g., /tmp/ssh-XXXX/agent.12345)",
				DefaultValue:     "",
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
		TaskFunctionProcessResponse: func(processResponse agentstructs.PtTaskProcessResponseMessage) agentstructs.PTTaskProcessResponseMessageResponse {
			response := agentstructs.PTTaskProcessResponseMessageResponse{
				TaskID:  processResponse.TaskData.Task.ID,
				Success: true,
			}
			responseText, ok := processResponse.Response.(string)
			if !ok || responseText == "" {
				return response
			}
			var creds []mythicrpc.MythicRPCCredentialCreateCredentialData
			var currentSocket string
			// Parse: Socket: /path (source) — N key(s)\n  [1] type SHA256:fp (bits) — comment
			for _, line := range strings.Split(responseText, "\n") {
				trimmed := strings.TrimSpace(line)
				if strings.HasPrefix(trimmed, "Socket:") {
					parts := strings.Fields(trimmed)
					if len(parts) >= 2 {
						currentSocket = parts[1]
					}
					continue
				}
				// Key lines: [N] type SHA256:fingerprint (bits) — comment
				if strings.HasPrefix(trimmed, "[") && strings.Contains(trimmed, "SHA256:") {
					parts := strings.SplitN(trimmed, "] ", 2)
					if len(parts) < 2 {
						continue
					}
					keyInfo := parts[1]
					fields := strings.Fields(keyInfo)
					if len(fields) < 2 {
						continue
					}
					keyType := fields[0]
					fingerprint := fields[1]
					comment := ""
					if idx := strings.Index(keyInfo, "— "); idx >= 0 {
						comment = keyInfo[idx+len("— "):]
					}
					creds = append(creds, mythicrpc.MythicRPCCredentialCreateCredentialData{
						CredentialType: "key",
						Realm:          "ssh-agent",
						Account:        comment,
						Credential:     fmt.Sprintf("type=%s fingerprint=%s socket=%s", keyType, fingerprint, currentSocket),
						Comment:        fmt.Sprintf("ssh-agent: %s key from %s", keyType, currentSocket),
					})
				}
			}
			registerCredentials(processResponse.TaskData.Task.ID, creds)
			return response
		},
		TaskFunctionOPSECPre: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTTaskOPSECPreTaskMessageResponse {
			return agentstructs.PTTTaskOPSECPreTaskMessageResponse{
				TaskID: taskData.Task.ID, Success: true,
				OpsecPreBlocked: false,
				OpsecPreMessage:    "OPSEC WARNING: Accessing SSH agent sockets (T1552.004). SSH agent hijacking allows key usage without file access. Socket access may be logged on hardened systems. Agent forwarding abuse is a known lateral movement technique.",
				OpsecPreBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionOPSECPost: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskOPSECPostTaskMessageResponse {
			return agentstructs.PTTaskOPSECPostTaskMessageResponse{
				TaskID:              taskData.Task.ID,
				Success:             true,
				OpsecPostBlocked:    false,
				OpsecPostMessage:    "OPSEC AUDIT: SSH agent enumeration completed. Accessing SSH agent socket reveals cached keys. Agent forwarding can be hijacked for lateral movement.",
				OpsecPostBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionCreateTasking: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  taskData.Task.ID,
			}
			action, _ := taskData.Args.GetStringArg("action")
			socket, _ := taskData.Args.GetStringArg("socket")
			display := action
			if socket != "" {
				display += " " + socket
			}
			response.DisplayParams = &display
			return response
		},
	})
}
