package agentfunctions

import (
	"fmt"
	"path/filepath"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "xattr",
		Description:         "Manage extended file attributes — list, get, set, delete. Unix complement to Windows ADS for hiding data in file metadata. Supports text and hex-encoded binary values.",
		HelpString:          "xattr -path /tmp/file.txt\nxattr -action get -path /tmp/file.txt -name user.secret\nxattr -action set -path /tmp/file.txt -name user.hidden -value 'secret data'\nxattr -action set -path /tmp/file.txt -name user.bin -value 48656c6c6f -hex true\nxattr -action delete -path /tmp/file.txt -name user.hidden",
		Version:             1,
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1564.004"},
		AssociatedBrowserScript: &agentstructs.BrowserScript{
			ScriptPath: filepath.Join(".", "fawkes", "browserscripts", "xattr_new.js"),
			Author:     "@galoryber",
		},
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{
				agentstructs.SUPPORTED_OS_LINUX,
				agentstructs.SUPPORTED_OS_MACOS,
			},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:          "action",
				CLIName:       "action",
				Description:   "Action to perform: list, get, set, delete (default: list)",
				DefaultValue:  "list",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:          "path",
				CLIName:       "path",
				Description:   "Target file path",
				DefaultValue:  "",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: true, GroupName: "Default"},
				},
			},
			{
				Name:          "name",
				CLIName:       "name",
				Description:   "Attribute name (e.g., user.secret). Required for get, set, delete.",
				DefaultValue:  "",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:          "value",
				CLIName:       "value",
				Description:   "Value to set (text or hex-encoded if -hex true)",
				DefaultValue:  "",
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:          "hex",
				CLIName:       "hex",
				Description:   "Treat value as hex-encoded binary (default: false)",
				DefaultValue:  false,
				ParameterType: agentstructs.COMMAND_PARAMETER_TYPE_BOOLEAN,
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
			action, _ := taskData.Args.GetStringArg("action")
			var msg string
			switch action {
			case "set":
				msg = "OPSEC WARNING: Setting extended attributes (T1564.004). Writing data to xattrs can hide payloads in file metadata. Monitored by auditd and file-integrity tools."
			case "delete":
				msg = "OPSEC WARNING: Deleting extended attributes (T1564.004). Removing xattrs may clear security labels (SELinux, macOS quarantine). Monitored by auditd."
			default:
				msg = "OPSEC WARNING: Reading extended attributes (T1564.004). Enumerating xattrs is low-risk but may reveal hidden data or security labels."
			}
			return agentstructs.PTTTaskOPSECPreTaskMessageResponse{
				TaskID: taskData.Task.ID, Success: true,
				OpsecPreBlocked:    false,
				OpsecPreMessage:    msg,
				OpsecPreBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionProcessResponse: func(processResponse agentstructs.PtTaskProcessResponseMessage) agentstructs.PTTaskProcessResponseMessageResponse {
			response := agentstructs.PTTaskProcessResponseMessageResponse{
				TaskID:  processResponse.TaskData.Task.ID,
				Success: true,
			}
			action, _ := processResponse.TaskData.Args.GetStringArg("action")
			path, _ := processResponse.TaskData.Args.GetStringArg("path")
			responseText, ok := processResponse.Response.(string)
			if !ok || responseText == "" || path == "" {
				return response
			}
			switch action {
			case "set":
				name, _ := processResponse.TaskData.Args.GetStringArg("name")
				createArtifact(processResponse.TaskData.Task.ID, "Data Hiding",
					fmt.Sprintf("xattr set %s on %s", name, path))
			case "delete":
				name, _ := processResponse.TaskData.Args.GetStringArg("name")
				createArtifact(processResponse.TaskData.Task.ID, "Indicator Removal",
					fmt.Sprintf("xattr delete %s from %s", name, path))
			case "list", "get":
				createArtifact(processResponse.TaskData.Task.ID, "File Discovery",
					fmt.Sprintf("xattr %s %s", action, path))
			}
			return response
		},
		TaskFunctionOPSECPost: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskOPSECPostTaskMessageResponse {
			return agentstructs.PTTaskOPSECPostTaskMessageResponse{
				TaskID:              taskData.Task.ID,
				Success:             true,
				OpsecPostBlocked:    false,
				OpsecPostMessage:    "OPSEC AUDIT: Extended attribute operation completed. xattr modifications alter file metadata without changing content — useful for hiding data but also detectable. On macOS, modifying com.apple.quarantine bypasses Gatekeeper. EDR may monitor xattr changes on sensitive files.",
				OpsecPostBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionCreateTasking: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  taskData.Task.ID,
			}
			action, _ := taskData.Args.GetStringArg("action")
			path, _ := taskData.Args.GetStringArg("path")
			display := fmt.Sprintf("%s %s", action, path)
			response.DisplayParams = &display
			return response
		},
	})
}
