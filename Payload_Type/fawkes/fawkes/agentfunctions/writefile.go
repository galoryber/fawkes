package agentfunctions

import (
	"fmt"
	"strings"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "write-file",
		Description:         "Write content to files, or deface web server pages. write: create/overwrite/append. deface: replace web content with attacker message (T1491).",
		HelpString:          "write-file -path /tmp/script.sh -content '#!/bin/bash\\necho hello'\nwrite-file -path /tmp/data.bin -content 'SGVsbG8=' -base64 true\nwrite-file -action deface -path /var/www/html/index.html -confirm DEFACE",
		Version:             2,
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1105", "T1059", "T1491"},
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
				Name:             "action",
				CLIName:          "action",
				ModalDisplayName: "Action",
				Description:      "write: normal file write (default). deface: replace web content with defacement message (T1491).",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:          []string{"write", "deface"},
				DefaultValue:     "write",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "confirm",
				CLIName:          "confirm",
				ModalDisplayName: "Safety Confirmation",
				Description:      "Type DEFACE to confirm defacement action (safety gate)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "path",
				CLIName:          "path",
				ModalDisplayName: "File Path",
				Description:      "Path to write to",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: true, GroupName: "Default"},
				},
			},
			{
				Name:             "content",
				CLIName:          "content",
				ModalDisplayName: "Content",
				Description:      "Text content to write (or base64-encoded data if -base64 true)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: true, GroupName: "Default"},
				},
			},
			{
				Name:             "base64",
				CLIName:          "base64",
				ModalDisplayName: "Base64 Decode",
				Description:      "Decode content from base64 before writing (for binary data)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_BOOLEAN,
				DefaultValue:     false,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "append",
				CLIName:          "append",
				ModalDisplayName: "Append Mode",
				Description:      "Append to file instead of overwriting (default: false)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_BOOLEAN,
				DefaultValue:     false,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "mkdir",
				CLIName:          "mkdir",
				ModalDisplayName: "Create Directories",
				Description:      "Create parent directories if they don't exist",
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
			action, _ := taskData.Args.GetStringArg("action")
			path, _ := taskData.Args.GetStringArg("path")
			var msg string
			if action == "deface" {
				msg = fmt.Sprintf("CRITICAL OPSEC WARNING: Web Defacement (T1491) — replacing content at %s with defacement message. "+
					"This is a visible, high-impact operation that will be immediately noticed by users and monitoring. "+
					"Web server access logs will record the file modification. FIM/HIDS will alert on content change. "+
					"Only proceed in authorized purple team exercises simulating defacement attacks.", path)
			} else {
				msg = fmt.Sprintf("OPSEC WARNING: Writing file to disk at: %s (T1105). File creation is logged by EDR and may trigger AV scanning. Suspicious paths (temp dirs, startup folders) increase detection risk.", path)
			}
			return agentstructs.PTTTaskOPSECPreTaskMessageResponse{
				TaskID: taskData.Task.ID, Success: true,
				OpsecPreBlocked: false, OpsecPreMessage: msg,
				OpsecPreBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionOPSECPost: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskOPSECPostTaskMessageResponse {
			return agentstructs.PTTaskOPSECPostTaskMessageResponse{
				TaskID:              taskData.Task.ID,
				Success:             true,
				OpsecPostBlocked:    false,
				OpsecPostMessage:    "OPSEC AUDIT: File write completed. New file or modified file on disk creates forensic artifacts in USN journal, MFT, and file system timestamps. EDR file monitoring may flag new executables.",
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
			display := fmt.Sprintf("%s", path)
			if action == "deface" {
				display = fmt.Sprintf("deface %s", path)
				createArtifact(taskData.Task.ID, "Impact", fmt.Sprintf("Web defacement (T1491): %s", path))
				logOperationEvent(taskData.Task.ID,
					fmt.Sprintf("[IMPACT] Web defacement started: %s", path), true)
			} else {
				createArtifact(taskData.Task.ID, "File Write", fmt.Sprintf("File write to %s", path))
			}
			response.DisplayParams = &display
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
			action, _ := processResponse.TaskData.Args.GetStringArg("action")
			if action == "deface" && strings.Contains(responseText, "Defaced") {
				tagTask(processResponse.TaskData.Task.ID, "IMPACT",
					"Web defacement: content replaced (T1491)")
				logOperationEvent(processResponse.TaskData.Task.ID,
					"[IMPACT] Web defacement completed (T1491)", true)
			}
			return response
		},
	})
}
