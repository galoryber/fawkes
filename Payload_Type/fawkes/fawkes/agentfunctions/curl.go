package agentfunctions

import (
	"fmt"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	agentstructs.AllPayloadData.Get("fawkes").AddCommand(agentstructs.Command{
		Name:                "curl",
		Description:         "Make HTTP/HTTPS requests from the agent's network perspective. Useful for cloud metadata, internal services, and SSRF.",
		HelpString:          "curl -url http://169.254.169.254/latest/meta-data/\ncurl -url https://internal-api.corp.local/health -method POST -body '{\"check\":true}' -headers '{\"Authorization\":\"Bearer token\"}'",
		Version:             1,
		Author:              "@galoryber",
		MitreAttackMappings: []string{"T1106"}, // Native API
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
		TaskFunctionCreateTasking: func(taskData *agentstructs.PTTaskMessageAllData) agentstructs.PTTaskCreateTaskingMessageResponse {
			response := agentstructs.PTTaskCreateTaskingMessageResponse{
				Success: true,
				TaskID:  taskData.Task.ID,
			}

			url, _ := taskData.Args.GetStringArg("url")
			method, _ := taskData.Args.GetStringArg("method")
			if method == "" {
				method = "GET"
			}

			displayMsg := fmt.Sprintf("%s %s", method, url)
			response.DisplayParams = &displayMsg

			createArtifact(taskData.Task.ID, "API Call",
				fmt.Sprintf("HTTP %s request to %s", method, url))

			return response
		},
	})
}
