package agentfunctions

import (
	"fmt"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
	"github.com/MythicMeta/MythicContainer/mythicrpc"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "smb",
		Description:         "SMB file operations on remote shares. List shares, browse directories, read/write/delete files via SMB2 with NTLM authentication. Supports pass-the-hash.",
		HelpString:          "smb -action shares -host 192.168.1.1 -username user -password pass -domain DOMAIN\nsmb -action ls -host 192.168.1.1 -share C$ -username admin -hash aad3b435b51404ee:8846f7eaee8fb117 -domain DOMAIN\nsmb -action cat -host 192.168.1.1 -share C$ -path Users/Public/file.txt -username admin -password pass",
		Version:             1,
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1021.002"},
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
				Description:      "Operation: shares (list shares), ls (list directory), cat (read file), upload (write file), rm (delete file)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:          []string{"shares", "ls", "cat", "upload", "rm"},
				DefaultValue:     "shares",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: true, GroupName: "Default"},
				},
			},
			{
				Name:             "host",
				CLIName:          "host",
				ModalDisplayName: "Target Host",
				Description:      "Remote host IP or hostname",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: true, GroupName: "Default"},
				},
			},
			{
				Name:             "username",
				CLIName:          "username",
				ModalDisplayName: "Username",
				Description:      "Username for NTLM auth (can include DOMAIN\\user or user@domain)",
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
				Description:      "Password for NTLM auth (or use -hash for pass-the-hash)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "hash",
				CLIName:          "hash",
				ModalDisplayName: "NTLM Hash",
				Description:      "NT hash for pass-the-hash (hex, e.g., aad3b435b51404ee:8846f7eaee8fb117 or just the NT hash)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "domain",
				CLIName:          "domain",
				ModalDisplayName: "Domain",
				Description:      "NTLM domain (auto-detected from username if DOMAIN\\user or user@domain format)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "share",
				CLIName:          "share",
				ModalDisplayName: "Share Name",
				Description:      "SMB share name (e.g., C$, ADMIN$, ShareName). Required for ls, cat, upload, rm.",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "path",
				CLIName:          "path",
				ModalDisplayName: "File/Directory Path",
				Description:      "Path within the share (e.g., Users/Public/file.txt). Required for cat, upload, rm. Optional for ls.",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "content",
				CLIName:          "content",
				ModalDisplayName: "File Content",
				Description:      "Content to write (for upload action only)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "port",
				CLIName:          "port",
				ModalDisplayName: "SMB Port",
				Description:      "SMB port (default: 445)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				DefaultValue:     445,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
		},
		TaskFunctionParseArgString: func(args *agentstructs.PTTaskMessageArgsData, input string) error {
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
			action, _ := taskData.Args.GetStringArg("action")
			share, _ := taskData.Args.GetStringArg("share")
			path, _ := taskData.Args.GetStringArg("path")

			displayMsg := fmt.Sprintf("SMB %s \\\\%s", action, host)
			if share != "" {
				displayMsg += fmt.Sprintf("\\%s", share)
			}
			if path != "" {
				displayMsg += fmt.Sprintf("\\%s", path)
			}
			response.DisplayParams = &displayMsg

			artifactMsg := fmt.Sprintf("SMB2 %s to %s", action, host)
			if share != "" {
				artifactMsg += fmt.Sprintf("\\%s", share)
			}
			mythicrpc.SendMythicRPCArtifactCreate(mythicrpc.MythicRPCArtifactCreateMessage{
				TaskID:           taskData.Task.ID,
				BaseArtifactType: "API Call",
				ArtifactMessage:  artifactMsg,
			})

			return response
		},
	})
}
