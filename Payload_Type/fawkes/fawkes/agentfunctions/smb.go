package agentfunctions

import (
	"fmt"
	"path/filepath"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
	"github.com/MythicMeta/MythicContainer/mythicrpc"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name: "smb",
		AssociatedBrowserScript: &agentstructs.BrowserScript{
			ScriptPath: filepath.Join(".", "fawkes", "browserscripts", "smb_new.js"),
			Author:     "@galoryber",
		},
		Description:         "SMB file operations on remote shares. List shares, browse, read/write/delete files, create directories, rename/move via SMB2 with NTLM auth. Pass-the-hash support.",
		HelpString:          "smb -action shares -host 192.168.1.1 -username user -password pass -domain DOMAIN\nsmb -action ls -host 192.168.1.1 -share C$ -username admin -hash aad3b435b51404ee:8846f7eaee8fb117 -domain DOMAIN\nsmb -action mkdir -host 192.168.1.1 -share C$ -path Users/Public/staging -username admin -password pass\nsmb -action mv -host 192.168.1.1 -share C$ -path old.txt -destination new.txt -username admin -password pass",
		Version:             2,
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1021.002", "T1550.002"},
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
				Description:      "Operation: shares (list shares), ls (list directory), cat (read file), upload (write file), rm (delete file), mkdir (create directory), mv (rename/move file)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:          []string{"shares", "ls", "cat", "upload", "rm", "mkdir", "mv"},
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
				Description:      "SMB share name (e.g., C$, ADMIN$, ShareName). Required for ls, cat, upload, rm, mkdir, mv.",
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
				Description:      "Path within the share. Required for cat, upload, rm, mkdir, mv. Optional for ls. For mv, this is the source path.",
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
				Name:             "destination",
				CLIName:          "destination",
				ModalDisplayName: "Destination Path",
				Description:      "Destination path within the share (for mv action — rename/move target)",
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
			action, _ := taskData.Args.GetStringArg("action")
			share, _ := taskData.Args.GetStringArg("share")
			msg := fmt.Sprintf("OPSEC WARNING: SMB %s operation on %s.", action, host)
			if share == "ADMIN$" || share == "C$" || share == "IPC$" {
				msg += fmt.Sprintf(" Accessing %s share — administrative share access is a high-fidelity lateral movement indicator.", share)
			}
			msg += " SMB connections generate Event ID 5140/5145 (share access) and 4624 (network logon)."
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
