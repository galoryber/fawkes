package agentfunctions

import (
	"fmt"
	"strings"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "chmod",
		Description:         "Modify file and directory permissions (octal or symbolic notation). Supports recursive directory operations.",
		HelpString:          "chmod -path /tmp/payload -mode 755\nchmod -path ./script.sh -mode +x\nchmod -path /var/data -mode 644 -recursive true\nchmod -path /tmp -mode u+rwx,go+rx",
		Version:             1,
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1222"},
		SupportedUIFeatures: []string{"file_browser:upload"},
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{
				agentstructs.SUPPORTED_OS_WINDOWS,
				agentstructs.SUPPORTED_OS_LINUX,
				agentstructs.SUPPORTED_OS_MACOS,
			},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:             "path",
				CLIName:          "path",
				ModalDisplayName: "File or Directory Path",
				Description:      "Path to file or directory to modify",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: true, GroupName: "Default"},
				},
			},
			{
				Name:             "mode",
				CLIName:          "mode",
				ModalDisplayName: "Permissions",
				Description:      "Octal mode (755, 644) or symbolic notation (+x, u+rw, go-w, a=rx)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: true, GroupName: "Default"},
				},
			},
			{
				Name:             "recursive",
				CLIName:          "recursive",
				ModalDisplayName: "Recursive",
				Description:      "Apply permissions recursively to directory contents",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_BOOLEAN,
				DefaultValue:     false,
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
			return agentstructs.PTTTaskOPSECPreTaskMessageResponse{
				TaskID: taskData.Task.ID, Success: true,
				OpsecPreBlocked:    false,
				OpsecPreMessage:    "OPSEC WARNING: Permission change (T1222). Modifying file permissions may trigger auditd/SELinux alerts or EDR file-integrity monitoring. Setting world-writable or SUID/SGID bits is especially suspicious.",
				OpsecPreBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionOPSECPost: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskOPSECPostTaskMessageResponse {
			return agentstructs.PTTaskOPSECPostTaskMessageResponse{
				TaskID:              taskData.Task.ID,
				Success:             true,
				OpsecPostBlocked:    false,
				OpsecPostMessage:    "OPSEC AUDIT: File permissions changed. Permission modifications logged in audit logs (auditd on Linux, SACL on Windows). Changes to executable permissions or SUID bits are high-priority monitoring targets.",
				OpsecPostBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionCreateTasking: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  taskData.Task.ID,
			}
			path, _ := taskData.Args.GetStringArg("path")
			mode, _ := taskData.Args.GetStringArg("mode")
			display := fmt.Sprintf("%s %s", mode, path)
			response.DisplayParams = &display
			createArtifact(taskData.Task.ID, "File Write", fmt.Sprintf("Permission change on %s", path))
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
			path, _ := processResponse.TaskData.Args.GetStringArg("path")
			mode, _ := processResponse.TaskData.Args.GetStringArg("mode")
			if strings.Contains(responseText, "success") || strings.Contains(responseText, "changed") || strings.Contains(responseText, "→") {
				createArtifact(processResponse.TaskData.Task.ID, "File Modification",
					fmt.Sprintf("chmod %s %s on %s", mode, path, processResponse.TaskData.Callback.Host))
			}
			return response
		},
	})
}
